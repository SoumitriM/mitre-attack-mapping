import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import HTTPException

from app.api.jobs import AnalysisJobs
from app.config import Settings
from app.main import app
from app.models import CVEAnalysis


@pytest.mark.asyncio
@pytest.mark.parametrize("compact", [True, False])
async def test_api_pending_until_entire_batch_finishes_and_polling_does_not_rerun(
    monkeypatch, compact
):
    first_ready, first_release = asyncio.Event(), asyncio.Event()
    second_ready, second_release = asyncio.Event(), asyncio.Event()
    calls = []

    async def runner(cve_ids, is_compact, source):
        calls.append((cve_ids, is_compact, source))
        first_ready.set()
        await first_release.wait()
        second_ready.set()
        await second_release.wait()
        if is_compact:
            return [{"cve_id": cve, "attack_chain": [], "ctid_map": {
                "exploitation_techniques": [], "primary_impacts": [], "secondary_impacts": [],
            }} for cve in cve_ids]
        return [CVEAnalysis(cve={"cve_id": cve}).model_dump(mode="json") for cve in cve_ids]

    monkeypatch.setattr("app.main.run_analysis_batch", runner)
    monkeypatch.setattr("app.api.routes.get_settings", lambda: Settings(neo4j_password="test"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        created = await client.post(f"/api/cve-analysis?compact={str(compact).lower()}", json={
            "cve_ids": [" cve-2024-3400 ", "CVE-2024-9474"],
        })
        assert created.status_code == 202
        accepted = created.json()
        assert accepted["status"] == "pending"
        assert set(accepted) == {"job_id", "status", "poll_url"}
        assert created.headers["location"] == accepted["poll_url"]
        await asyncio.wait_for(first_ready.wait(), 1)
        for _ in range(3):
            pending = await client.get(accepted["poll_url"])
            assert pending.json() == accepted
            assert pending.headers["cache-control"] == "no-store"
            assert pending.headers["retry-after"] == "3"
        first_release.set()
        await asyncio.wait_for(second_ready.wait(), 1)
        assert (await client.get(accepted["poll_url"])).json() == accepted
        second_release.set()
        await asyncio.sleep(0)
        done = await client.get(accepted["poll_url"])
        body = done.json()
        assert body["status"] == "completed"
        assert body["job_id"] == accepted["job_id"]
        ids = [r["cve_id"] if compact else r["cve"]["cve_id"] for r in body["results"]]
        assert ids == ["CVE-2024-3400", "CVE-2024-9474"]
        assert (await client.get(accepted["poll_url"])).json() == body
        assert calls == [(["CVE-2024-3400", "CVE-2024-9474"], compact, "auto")]


@pytest.mark.asyncio
async def test_api_validates_before_creating_job_and_unknown_job_returns_404(monkeypatch):
    runner = AsyncMock(return_value=[])
    monkeypatch.setattr("app.main.run_analysis_batch", runner)
    monkeypatch.setattr("app.api.routes.get_settings", lambda: Settings(neo4j_password="test"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        for payload in [{"cve_ids": []}, {"cve_ids": ["bad"]},
                        {"cve_ids": ["CVE-2024-3400"], "description_source": "bad"}]:
            assert (await client.post("/api/cve-analysis", json=payload)).status_code == 422
        assert (await client.get("/api/cve-analysis/unknown")).status_code == 404
        runner.assert_not_awaited()


@pytest.mark.asyncio
async def test_api_failure_is_terminal_and_keeps_provider_secrets_out(monkeypatch):
    runner = AsyncMock(side_effect=RuntimeError("secret provider key"))
    monkeypatch.setattr("app.main.run_analysis_batch", runner)
    monkeypatch.setattr("app.api.routes.get_settings", lambda: Settings(neo4j_password="test"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        created = (await client.post("/api/cve-analysis", json={
            "cve_ids": ["CVE-2024-3400"], "description_source": "advisories",
        })).json()
        await asyncio.sleep(0)
        failed = (await client.get(created["poll_url"])).json()
        assert failed["status"] == "failed"
        assert failed["error"]["code"] == 500
        assert "secret provider key" not in str(failed)
        assert "results" not in failed
        assert (await client.get(created["poll_url"])).json() == failed
        runner.assert_awaited_once_with(["CVE-2024-3400"], True, "advisories")


@pytest.mark.asyncio
async def test_capacity_retention_concurrency_and_pending_jobs_do_not_expire():
    now = [0.0]
    started, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def runner(cve_ids, compact, source):
        calls.append(cve_ids)
        started.set()
        await release.wait()
        return []

    jobs = AnalysisJobs(runner, capacity=2, concurrency=1, retention_seconds=10,
                        clock=lambda: now[0])
    first = jobs.submit(["CVE-2024-3400"], True, "auto")
    second = jobs.submit(["CVE-2024-9474"], True, "auto")
    await asyncio.wait_for(started.wait(), 1)
    assert calls == [["CVE-2024-3400"]]
    now[0] = 100.0
    assert jobs.get(first.job_id).status == "pending"
    assert jobs.get(second.job_id).status == "pending"
    with pytest.raises(HTTPException) as error:
        jobs.submit(["CVE-2024-0012"], True, "auto")
    assert error.value.status_code == 503
    release.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert jobs.get(first.job_id).status == "completed"
    assert jobs.get(second.job_id).status == "completed"
    now[0] = 111.0
    with pytest.raises(HTTPException) as error:
        jobs.get(first.job_id)
    assert error.value.status_code == 404
    jobs.submit(["CVE-2024-0012"], True, "auto")
    await jobs.close()
    with pytest.raises(HTTPException):
        jobs.submit(["CVE-2024-0012"], True, "auto")


@pytest.mark.asyncio
async def test_shutdown_cancels_active_runner_and_runs_its_cleanup():
    started, cleaned = asyncio.Event(), asyncio.Event()

    async def runner(cve_ids, compact, source):
        try:
            started.set()
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    jobs = AnalysisJobs(runner)
    jobs.submit(["CVE-2024-3400"], True, "auto")
    await asyncio.wait_for(started.wait(), 1)
    await jobs.close()
    assert cleaned.is_set()


@pytest.mark.asyncio
async def test_unmapped_ids_remain_null_in_completed_json(monkeypatch):
    result = {"cve_id": "CVE-2024-3400", "attack_chain": [{
        "step": 1, "action": "An unsupported action", "technique_id": None,
        "tactic_id": None, "confidence": 0.0, "mapped": False,
    }], "ctid_map": {"exploitation_techniques": [], "primary_impacts": [],
                    "secondary_impacts": []}}
    monkeypatch.setattr("app.main.run_analysis_batch", AsyncMock(return_value=[result]))
    monkeypatch.setattr("app.api.routes.get_settings", lambda: Settings(neo4j_password="test"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        job = (await client.post("/api/cve-analysis", json={
            "cve_ids": ["CVE-2024-3400"],
        })).json()
        await asyncio.sleep(0)
        done = (await client.get(job["poll_url"])).json()
        assert done["results"][0]["attack_chain"][0]["technique_id"] is None
        assert done["results"][0]["attack_chain"][0]["tactic_id"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("graph_fails", [True, False])
async def test_batch_runner_releases_neo4j_and_model_clients(monkeypatch, graph_fails):
    from unittest.mock import MagicMock

    from app.api.routes import run_analysis_batch
    from app.graph.repository import GraphUnavailable

    driver = MagicMock(close=AsyncMock())
    inference = MagicMock(close=AsyncMock())
    agent = MagicMock(client=inference, downstream_client=inference)
    graph = MagicMock(initialize=AsyncMock(
        side_effect=GraphUnavailable("taxonomy missing") if graph_fails else None
    ))
    service = MagicMock(analyze=AsyncMock(side_effect=lambda cve, **kwargs: CVEAnalysis(
        cve={"cve_id": cve}
    )))
    monkeypatch.setattr("app.api.routes.get_settings", lambda: Settings(
        neo4j_password="test", ctid_only_mode=False, enable_ctid_mapping=False,
    ))
    monkeypatch.setattr("app.api.routes.AsyncGraphDatabase.driver", lambda *args, **kwargs: driver)
    monkeypatch.setattr("app.api.routes.FHGenieEvidenceAgent", lambda settings: agent)
    monkeypatch.setattr("app.api.routes.GraphRepository", lambda *args, **kwargs: graph)
    monkeypatch.setattr("app.api.routes.CVEAnalysisService", lambda *args, **kwargs: service)
    if graph_fails:
        with pytest.raises(HTTPException) as error:
            await run_analysis_batch(["CVE-2024-3400"], True, "auto")
        assert error.value.status_code == 503
    else:
        records = await run_analysis_batch(["CVE-2024-9474", "CVE-2024-3400"], True, "auto")
        assert [r["cve_id"] for r in records] == ["CVE-2024-9474", "CVE-2024-3400"]
        assert all(call.kwargs["description_source"] == "auto"
                   for call in service.analyze.await_args_list)
    driver.close.assert_awaited_once()
    inference.close.assert_awaited_once()
