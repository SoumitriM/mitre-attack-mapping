from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.analysis import CVEAnalysisService
from app.config import Settings
from app.enrichment.fh_genie import DescriptionEvidence, ExtractionResponseError
from app.ingestion.description import description_has_exploit_behavior
from app.models import CVERecord, ExploitStep, SourceAttribution

RICH = (
    "A command injection in web components allows an authenticated administrator "
    "to send crafted requests and execute arbitrary commands."
)


@pytest.mark.parametrize("text", [
    RICH,
    "An authentication bypass in the web interface allows an attacker to gain privileges.",
    "Malicious code was discovered in the upstream tarballs of xz.",
    "A privilege escalation allows an administrator to perform actions with root privileges.",
    "A Spring MVC application permits remote code execution via data binding.",
])
def test_accepts_descriptions_with_exploit_mechanisms(text):
    assert description_has_exploit_behavior(text)


@pytest.mark.parametrize("text", [
    None, "", "Microsoft Outlook Elevation of Privilege Vulnerability",
    "Sensitive information disclosure in NetScaler Gateway when configured as a Gateway.",
    "A critical issue impacts many versions. Install the security update immediately.",
])
def test_rejects_title_only_and_generic_descriptions(text):
    assert not description_has_exploit_behavior(text)


@pytest.fixture
def service(monkeypatch):
    cve = CVERecord(
        cve_id="CVE-2024-21887", description=RICH,
        sources=[SourceAttribution(
            name="NVD", url="https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
            retrieved_at=datetime.now(UTC),
        )],
        field_provenance={"description": ["NVD"]},
    )
    monkeypatch.setattr("app.analysis.CVEIngestionService.analyze", AsyncMock(return_value=cve))
    monkeypatch.setattr("app.analysis.fetch_opencve_description", AsyncMock(return_value=(
        DescriptionEvidence("OpenCVE", "https://app.opencve.io/cve/CVE-2024-21887", RICH)
    )))
    graph = MagicMock()
    graph.verify_taxonomy = AsyncMock()
    agent = MagicMock()
    agent.extract = AsyncMock(return_value=[ExploitStep.model_validate({
        "step": 1, "action": "Send crafted requests to execute commands",
        "evidence": [{"source_url": "https://app.opencve.io/cve/CVE-2024-21887",
                      "supporting_text": RICH}],
    })])
    svc = CVEAnalysisService(Settings(ctid_only_mode=False, enable_ctid_mapping=False),
                             graph, MagicMock(), agent)
    svc._fetch_advisories = AsyncMock(return_value=([], [], []))
    return svc


@pytest.mark.asyncio
async def test_rich_description_avoids_advisories(service):
    result = await service.analyze("CVE-2024-21887")
    service._fetch_advisories.assert_not_awaited()
    assert service.agent.extract.await_count == 1
    assert service.agent.extract.call_args.args[1] == []
    assert result.description_evidence.source_name == "OpenCVE"
    assert result.exploit_steps


@pytest.mark.asyncio
async def test_sparse_description_fetches_advisories_before_extraction(service, monkeypatch):
    monkeypatch.setattr("app.analysis.fetch_opencve_description", AsyncMock(return_value=(
        DescriptionEvidence("OpenCVE", "https://app.opencve.io/cve/CVE-2024-21887", "Title only")
    )))
    fetched = [MagicMock()]
    service._fetch_advisories.return_value = (fetched, [], [])
    await service.analyze("CVE-2024-21887")
    service._fetch_advisories.assert_awaited_once()
    assert service.agent.extract.await_count == 1
    assert service.agent.extract.call_args.args[1] is fetched


@pytest.mark.asyncio
async def test_empty_extraction_uses_new_advisory_evidence(service):
    extracted = service.agent.extract.return_value
    fetched = [MagicMock()]
    service._fetch_advisories.return_value = (fetched, [], [])
    service.agent.extract.side_effect = [[], extracted]
    result = await service.analyze("CVE-2024-21887")
    service._fetch_advisories.assert_awaited_once()
    assert service.agent.extract.await_count == 2
    calls = service.agent.extract.await_args_list
    assert calls[0].args[1] == []
    assert calls[1].args[1] is fetched
    assert result.exploit_steps == extracted


@pytest.mark.asyncio
async def test_no_advisory_does_not_repeat_empty_extraction(service):
    service.agent.extract.return_value = []
    result = await service.analyze("CVE-2024-21887")
    assert service.agent.extract.await_count == 1
    assert not result.exploit_steps
    assert "No exploit steps were extracted from the available evidence" in result.warnings


@pytest.mark.asyncio
async def test_model_failure_is_not_retried_as_advisory_fallback(service):
    service.agent.extract.side_effect = ExtractionResponseError("model failed")
    result = await service.analyze("CVE-2024-21887")
    service._fetch_advisories.assert_not_awaited()
    assert service.agent.extract.await_count == 1
    assert result.description_evidence.extraction_status == "extraction_failed"


@pytest.mark.asyncio
async def test_opencve_failure_uses_rich_authoritative_description(service, monkeypatch):
    monkeypatch.setattr("app.analysis.fetch_opencve_description", AsyncMock(
        side_effect=httpx.ConnectError("unavailable")
    ))
    result = await service.analyze("CVE-2024-21887")
    service._fetch_advisories.assert_not_awaited()
    assert result.description_evidence.source_name == "NVD"
    assert result.cve.field_provenance["description"] == ["NVD"]
    assert any("OpenCVE description unavailable" in x for x in result.warnings)


@pytest.mark.asyncio
async def test_sparse_description_without_advisories_skips_inference(service, monkeypatch):
    monkeypatch.setattr("app.analysis.fetch_opencve_description", AsyncMock(return_value=(
        DescriptionEvidence("OpenCVE", "https://app.opencve.io/cve/CVE-2024-21887", "Title only")
    )))
    result = await service.analyze("CVE-2024-21887")
    service._fetch_advisories.assert_awaited_once()
    service.agent.extract.assert_not_awaited()
    assert not result.exploit_steps
    assert any("extraction was skipped" in warning for warning in result.warnings)
