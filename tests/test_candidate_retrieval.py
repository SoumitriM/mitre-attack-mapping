import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.enrichment.candidate_retrieval import (
    RERANK_LIMIT,
    VECTOR_RETRIEVAL_LIMIT,
    RerankEnvelope,
    behavior_query,
    canonical_attack_document,
    embedding_cache_key,
    rerank_candidates,
    save_retrieval_log,
    top_vector_candidates,
)
from app.models import ExploitStep


def step() -> ExploitStep:
    return ExploitStep.model_validate(
        {
            "step": 5,
            "action": "Register abandoned domain",
            "prerequisites": ["The former vendor domain is unregistered"],
            "outcome": "Attacker controls the update domain",
            "evidence": [
                {
                    "source_url": "https://example.test/advisory",
                    "supporting_text": "An unaffiliated party registered the abandoned domain.",
                }
            ],
        }
    )


def record(number: int, technique_id: str | None = None) -> dict[str, object]:
    return {
        "mitre_technique_id": technique_id or f"T{number:04d}",
        "name": "Acquire Infrastructure: Domains" if technique_id else f"Technique {number}",
        "description": "Adversaries may acquire domains for targeting."
        if technique_id
        else "Official description",
        "tactics": [{"name": "resource-development", "id": "TA0042"}],
        "platforms": ["Windows"],
    }


def response(ids: list[str]) -> SimpleNamespace:
    content = json.dumps(
        {
            "candidates": [
                {
                    "mitre_technique_id": item,
                    "reasoning": "Semantic match",
                    "rerank_score": 1 - index / 100,
                }
                for index, item in enumerate(ids)
            ]
        }
    )
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def test_query_contains_only_atomic_step_fields() -> None:
    query = behavior_query(step())
    assert query == (
        "Register abandoned domain The former vendor domain is unregistered "
        "Attacker controls the update domain An unaffiliated party registered "
        "the abandoned domain."
    )
    assert "ATT&CK" not in query


def test_canonical_document_contains_only_authoritative_embedding_fields() -> None:
    item = {**record(1, "T1583.001"), "cwe": "forbidden", "detection": "forbidden"}
    assert canonical_attack_document(item) == (
        "MITRE ATT&CK Technique: T1583.001\nName: Acquire Infrastructure: Domains\n"
        "Tactics: resource-development\nPlatforms: Windows\n"
        "Description: Adversaries may acquire domains for targeting."
    )
    assert "forbidden" not in canonical_attack_document(item)


def test_cache_key_changes_for_every_embedded_field_and_model() -> None:
    original = record(1, "T1583.001")
    original_key = embedding_cache_key(original, "model-a")
    variants = [
        embedding_cache_key({**original, field: value}, "model-a")
        for field, value in (
            ("mitre_technique_id", "T9999"),
            ("name", "Changed"),
            ("description", "Changed"),
            ("platforms", ["Linux"]),
            ("tactics", [{"name": "execution", "id": "TA0002"}]),
        )
    ] + [embedding_cache_key(original, "model-b")]
    assert all(item != original_key for item in variants)


def test_abandoned_domain_appears_in_top_20_vector_candidates() -> None:
    records = [record(i) for i in range(30)]
    records[24] = record(24, "T1583.001")
    scores = {item["mitre_technique_id"]: index / 100 for index, item in enumerate(records)}
    scores["T1583.001"] = 0.995
    candidates = top_vector_candidates(records, scores)
    assert len(candidates) == VECTOR_RETRIEVAL_LIMIT == 20
    assert candidates[0]["mitre_technique_id"] == "T1583.001"


@pytest.mark.asyncio
async def test_reranker_returns_exactly_top_10_supplied_candidates() -> None:
    candidates = [{**record(i), "vector_score": 1 - i / 100} for i in range(20)]
    ids = [item["mitre_technique_id"] for item in reversed(candidates[:RERANK_LIMIT])]
    client = MagicMock()
    client.chat.completions.create = AsyncMock(return_value=response(ids))
    ranked, metadata = await rerank_candidates(client, "fh-genie", step(), candidates)
    assert [item["mitre_technique_id"] for item in ranked] == ids
    assert len(metadata) == RERANK_LIMIT
    payload = json.loads(client.chat.completions.create.await_args.kwargs["messages"][1]["content"])
    assert len(payload["candidates"]) == VECTOR_RETRIEVAL_LIMIT
    assert "description" in payload["candidates"][0]
    assert client.chat.completions.create.await_args.kwargs["max_completion_tokens"] == 8192


@pytest.mark.asyncio
async def test_reranker_rejects_invented_candidate() -> None:
    candidates = [{**record(i), "vector_score": 0.5} for i in range(10)]
    ids = [item["mitre_technique_id"] for item in candidates[:-1]] + ["T9999"]
    client = MagicMock()
    client.chat.completions.create = AsyncMock(return_value=response(ids))
    with pytest.raises(ValueError, match="unsupplied"):
        await rerank_candidates(client, "fh-genie", step(), candidates)


def test_retrieval_log_contains_both_stages(tmp_path, monkeypatch) -> None:
    import app.enrichment.candidate_retrieval as retrieval

    monkeypatch.setattr(retrieval, "RETRIEVAL_LOG_DIR", tmp_path)
    candidates = [{**record(1, "T1583.001"), "vector_score": 0.81}]
    reranked = RerankEnvelope.model_validate_json(
        response(["T1583.001"]).choices[0].message.content
    ).candidates
    path = save_retrieval_log(
        cve_id="CVE-2026-22306",
        step=step(),
        query_text=behavior_query(step()),
        vector_candidates=candidates,
        reranked=reranked,
    )
    payload = json.loads(path.read_text())
    assert (payload["cve_id"], payload["step"], payload["action"]) == (
        "CVE-2026-22306",
        5,
        "Register abandoned domain",
    )
    assert payload["vector_candidates"][0]["id"] == "T1583.001"
    assert payload["reranked_candidates"][0]["id"] == "T1583.001"
