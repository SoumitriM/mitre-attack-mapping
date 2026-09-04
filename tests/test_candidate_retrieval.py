import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.enrichment.candidate_retrieval import (
    BM25_RETRIEVAL_LIMIT,
    RERANK_LIMIT,
    VECTOR_RETRIEVAL_LIMIT,
    RerankEnvelope,
    attack_embedding_documents,
    behavior_query,
    bm25_scores,
    bm25_tokens,
    canonical_attack_document,
    combine_candidates,
    compact_description,
    embedding_cache_key,
    normalized_behavior_query,
    rerank_candidates,
    rerank_system_prompt,
    save_retrieval_log,
    top_bm25_candidates,
    top_vector_candidates,
    vector_similarity_scores,
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
    item = {
        **record(1, "T1583.001"),
        "procedure_examples": ["Example Group registered a domain."],
        "cwe": "forbidden",
        "detection": "forbidden",
    }
    assert canonical_attack_document(item) == (
        "MITRE ATT&CK Technique: T1583.001\nName: Acquire Infrastructure: Domains\n"
        "Tactics: resource-development\nPlatforms: Windows\n"
        "Description: Adversaries may acquire domains for targeting.\n"
        "Procedure Examples: Example Group registered a domain."
    )
    assert "forbidden" not in canonical_attack_document(item)


@pytest.mark.asyncio
async def test_normalizes_behavior_for_vector_retrieval() -> None:
    client = MagicMock()
    client.chat.completions.create = AsyncMock(
        return_value=SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({
                "normalized_query": (
                    "Exploit an unauthenticated vulnerability in a public-facing application "
                    "using a crafted request to achieve remote code execution."
                )
            })))]
        )
    )
    normalized = await normalized_behavior_query(client, "fh-genie", step())
    assert normalized.startswith("Exploit an unauthenticated vulnerability")
    payload = json.loads(client.chat.completions.create.await_args.kwargs["messages"][1]["content"])
    assert payload["action"] == step().action
    assert client.chat.completions.create.await_args.kwargs["max_completion_tokens"] == 2048


@pytest.mark.asyncio
async def test_empty_normalized_query_logs_response_metadata(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = MagicMock()
    client.chat.completions.create = AsyncMock(
        return_value=SimpleNamespace(
            id="response-123",
            model="fh-genie",
            usage=SimpleNamespace(model_dump=lambda: {"completion_tokens": 2048}),
            choices=[SimpleNamespace(
                finish_reason="length",
                message=SimpleNamespace(content="", reasoning_content="internal reasoning"),
            )],
        )
    )

    with (
        caplog.at_level("WARNING"),
        pytest.raises(ValueError, match="Empty FH Genie normalized-query response"),
    ):
        await normalized_behavior_query(client, "fh-genie", step())

    record = next(
        item for item in caplog.records
        if item.getMessage().startswith("Empty FH Genie normalized-query response metadata")
    )
    assert record.fh_genie_response_metadata == {
        "response_id": "response-123",
        "model": "fh-genie",
        "finish_reason": "length",
        "reasoning_content_length": 18,
        "usage": {"completion_tokens": 2048},
    }


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
            ("procedure_examples", ["A group used this technique."]),
        )
    ] + [embedding_cache_key(original, "model-b")]
    assert all(item != original_key for item in variants)


def test_embedding_documents_preserve_all_procedures_with_bounded_chunks() -> None:
    procedures = [f"Procedure {index}: " + "behavior " * 200 for index in range(10)]
    documents = attack_embedding_documents({
        **record(1, "T1105"),
        "procedure_examples": procedures,
    })
    assert len(documents) > 1
    assert all(len(document) <= 6000 for document in documents)
    assert all(procedure.strip() in " ".join(documents) for procedure in procedures)


def test_vector_similarity_uses_best_procedure_chunk() -> None:
    scores = vector_similarity_scores(
        [1.0, 0.0],
        [record(1, "T1105")],
        {"T1105": [[0.0, 1.0], [1.0, 0.0]]},
    )
    assert scores["T1105"] == 1.0


def test_abandoned_domain_appears_in_top_20_vector_candidates() -> None:
    records = [record(i) for i in range(30)]
    records[24] = record(24, "T1583.001")
    scores = {item["mitre_technique_id"]: index / 100 for index, item in enumerate(records)}
    scores["T1583.001"] = 0.995
    candidates = top_vector_candidates(records, scores)
    assert len(candidates) == VECTOR_RETRIEVAL_LIMIT == 20
    assert candidates[0]["mitre_technique_id"] == "T1583.001"


def test_bm25_tokenization_is_case_insensitive_and_preserves_mechanisms() -> None:
    assert bm25_tokens("SQL Injection via COPY_TO/PROGRAM") == [
        "sql",
        "injection",
        "via",
        "copy_to/program",
    ]


def test_bm25_recovers_public_facing_exploitation_candidate() -> None:
    records = [record(i) for i in range(30)]
    records[24] = {
        **record(24, "T1190"),
        "name": "Exploit Public-Facing Application",
        "description": (
            "Adversaries may exploit a weakness in an Internet-facing host or system."
        ),
    }
    scores = bm25_scores(
        "Exploit SQL injection in a public-facing application", records
    )
    candidates = top_bm25_candidates(records, scores)
    assert len(candidates) == BM25_RETRIEVAL_LIMIT == 20
    assert candidates[0]["mitre_technique_id"] == "T1190"


def test_hybrid_union_deduplicates_and_preserves_source_metadata() -> None:
    shared = record(1, "T1190")
    lexical = [{**shared, "bm25_score": 4.2}, {**record(2), "bm25_score": 2.1}]
    vectors = [{**shared, "vector_score": 0.9}, {**record(3), "vector_score": 0.8}]
    combined = combine_candidates(lexical, vectors)
    assert len(combined) == 3
    overlap = next(item for item in combined if item["mitre_technique_id"] == "T1190")
    assert (overlap["bm25_rank"], overlap["vector_rank"]) == (1, 1)
    assert (overlap["bm25_score"], overlap["vector_score"]) == (4.2, 0.9)


def test_reranker_description_is_compacted_at_a_word_boundary() -> None:
    compacted = compact_description("behavior " * 500)
    assert len(compacted) <= 1201
    assert compacted.endswith("…")


def test_rerank_prompt_contains_only_request_specific_technique_ids() -> None:
    candidates = [record(1, "T1583.001"), record(2, "T1584.001")]
    prompt = rerank_system_prompt(candidates, expected_count=2)
    assert 'ALLOWED_TECHNIQUE_IDS=["T1583.001", "T1584.001"]' in prompt
    assert "T1059.003" not in prompt
    assert "Unix shell" not in prompt
    assert "Return exactly 2 candidates" in prompt


@pytest.mark.asyncio
async def test_reranker_returns_exactly_top_5_supplied_candidates() -> None:
    candidates = [{**record(i), "vector_score": 1 - i / 100} for i in range(20)]
    ids = [item["mitre_technique_id"] for item in reversed(candidates[:RERANK_LIMIT])]
    client = MagicMock()
    client.chat.completions.create = AsyncMock(return_value=response(ids))
    ranked, metadata = await rerank_candidates(client, "fh-genie", step(), candidates)
    assert [item["mitre_technique_id"] for item in ranked] == ids
    assert len(metadata) == RERANK_LIMIT
    payload = json.loads(client.chat.completions.create.await_args.kwargs["messages"][1]["content"])
    system_prompt = client.chat.completions.create.await_args.kwargs["messages"][0]["content"]
    assert len(payload["candidates"]) == VECTOR_RETRIEVAL_LIMIT
    assert "description" in payload["candidates"][0]
    assert all(item in system_prompt for item in ids)
    assert "T1059.003" not in system_prompt
    assert client.chat.completions.create.await_args.kwargs["max_completion_tokens"] == 8192


@pytest.mark.asyncio
async def test_reranker_rejects_invented_candidate() -> None:
    candidates = [{**record(i), "vector_score": 0.5} for i in range(10)]
    ids = [item["mitre_technique_id"] for item in candidates[:4]] + ["T9999"]
    client = MagicMock()
    client.chat.completions.create = AsyncMock(return_value=response(ids))
    with pytest.raises(ValueError, match="unsupplied"):
        await rerank_candidates(client, "fh-genie", step(), candidates)


def test_retrieval_log_contains_both_stages(tmp_path, monkeypatch) -> None:
    import app.enrichment.candidate_retrieval as retrieval

    monkeypatch.setattr(retrieval, "RETRIEVAL_LOG_DIR", tmp_path)
    lexical = [{**record(1, "T1583.001"), "bm25_score": 2.4}]
    candidates = [{**record(1, "T1583.001"), "vector_score": 0.81}]
    combined = combine_candidates(lexical, candidates)
    reranked = RerankEnvelope.model_validate_json(
        response(["T1583.001"]).choices[0].message.content
    ).candidates
    path = save_retrieval_log(
        cve_id="CVE-2026-22306",
        step=step(),
        query_text=behavior_query(step()),
        normalized_query_text="Acquire control of infrastructure by registering a domain.",
        bm25_candidates=lexical,
        vector_candidates=candidates,
        combined_candidates=combined,
        reranked=reranked,
    )
    payload = json.loads(path.read_text())
    assert (payload["cve_id"], payload["step"], payload["action"]) == (
        "CVE-2026-22306",
        5,
        "Register abandoned domain",
    )
    assert payload["vector_candidates"][0]["id"] == "T1583.001"
    assert payload["bm25_candidates"][0]["id"] == "T1583.001"
    assert payload["combined_candidates"][0]["id"] == "T1583.001"
    assert payload["overlap_count"] == 1
    assert payload["raw_bm25_query"] == behavior_query(step())
    assert payload["normalized_vector_query"].startswith("Acquire control")
    assert payload["reranked_candidates"][0]["id"] == "T1583.001"
