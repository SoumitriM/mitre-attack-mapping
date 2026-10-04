import json
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.enrichment.candidate_retrieval import behavior_query, embedding_cache_key
from app.graph.repository import GraphRepository, GraphUnavailable
from app.models import (
    ExploitStep,
)


class AsyncRecords:
    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = records

    def __aiter__(self) -> AsyncIterator[dict[str, object]]:
        async def iterate() -> AsyncIterator[dict[str, object]]:
            for record in self.records:
                yield record

        return iterate()


@pytest.mark.asyncio
async def test_description_retrieval_batches_normalized_items_when_cache_is_warm() -> None:
    record = {
        "mitre_technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Exploit a weakness in an Internet-facing system.",
        "platforms": ["Linux"],
        "procedure_examples": [],
        "tactics": [{"name": "initial-access", "id": "TA0001"}],
    }
    session = MagicMock()
    session.run = AsyncMock(return_value=AsyncRecords([record]))
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    client = MagicMock()
    client.embeddings.create = AsyncMock(
        return_value=MagicMock(
            data=[
                MagicMock(embedding=[1.0, 0.0]),
                MagicMock(embedding=[1.0, 0.0]),
                MagicMock(embedding=[1.0, 0.0]),
            ]
        )
    )
    GraphRepository._description_embedding_cache["embedding-model"] = {
        "T1190": (embedding_cache_key(record, "embedding-model"), [[1.0, 0.0]])
    }

    candidates = await GraphRepository(
        driver, client, "embedding-model"
    ).description_attack_candidates(
        "CVE-2026-0001",
        {
            "exploitation_behaviors": ["Exploit an Internet-facing vulnerability"],
            "primary_capabilities": ["Gain code execution"],
            "secondary_behaviors": ["Execute a command"],
        },
    )

    assert candidates["exploitation"][0].mitre_technique_id == "T1190"
    assert candidates["exploitation"][0].retrieved_by == ["exploitation_behaviors[0]"]
    assert candidates["primary_impact"][0].retrieved_by == ["primary_capabilities[0]"]
    assert candidates["secondary_impact"][0].retrieved_by == ["secondary_behaviors[0]"]
    client.embeddings.create.assert_awaited_once()
    assert client.embeddings.create.await_args.kwargs["input"] == [
        "Exploit an Internet-facing vulnerability",
        "Gain code execution",
        "Execute a command",
    ]


@pytest.mark.asyncio
async def test_description_retrieval_does_not_build_cold_cache_during_request(tmp_path) -> None:
    record = {
        "mitre_technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Exploit a weakness in an Internet-facing system.",
        "platforms": ["Linux"],
        "procedure_examples": [],
        "tactics": [{"name": "initial-access", "id": "TA0001"}],
    }
    session = MagicMock()
    session.run = AsyncMock(return_value=AsyncRecords([record]))
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    client = MagicMock()
    client.embeddings.create = AsyncMock()
    model = "cold-cache-model"
    GraphRepository._description_embedding_cache.pop(model, None)

    repository = GraphRepository(
        driver,
        client,
        model,
        attack_embedding_cache_path=tmp_path / "missing.json",
    )
    with pytest.raises(GraphUnavailable, match="cache is missing or stale"):
        await repository.description_attack_candidates(
            "CVE-2026-0002",
            {
                "exploitation_behaviors": ["Exploit an exposed service"],
                "primary_capabilities": [],
                "secondary_behaviors": [],
            },
        )

    client.embeddings.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_persisted_description_cache_is_reused_with_one_query_call(tmp_path) -> None:
    record = {
        "mitre_technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Exploit a weakness in an Internet-facing system.",
        "platforms": ["Linux"],
        "procedure_examples": [],
        "tactics": [{"name": "initial-access", "id": "TA0001"}],
    }
    model = "persisted-cache-model"
    cache_path = tmp_path / "attack-embeddings.json"
    cache_path.write_text(
        json.dumps(
            {
                "embedding_model": model,
                "techniques": {
                    "T1190": {
                        "cache_key": embedding_cache_key(record, model),
                        "vectors": [[1.0, 0.0]],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    GraphRepository._description_embedding_cache.pop(model, None)
    session = MagicMock()
    session.run = AsyncMock(return_value=AsyncRecords([record]))
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    client = MagicMock()
    client.embeddings.create = AsyncMock(
        return_value=MagicMock(data=[MagicMock(embedding=[1.0, 0.0])])
    )

    candidates = await GraphRepository(
        driver,
        client,
        model,
        attack_embedding_cache_path=cache_path,
    ).description_attack_candidates(
        "CVE-2026-0003",
        {
            "exploitation_behaviors": ["Exploit an exposed service"],
            "primary_capabilities": [],
            "secondary_behaviors": [],
        },
    )

    assert [candidate.mitre_technique_id for candidate in candidates["exploitation"]] == ["T1190"]
    client.embeddings.create.assert_awaited_once()
    assert client.embeddings.create.await_args.kwargs["input"] == ["Exploit an exposed service"]


@pytest.mark.asyncio
async def test_duplicate_role_candidates_preserve_normalized_item_provenance() -> None:
    record = {
        "mitre_technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Exploit a weakness in an Internet-facing system.",
        "platforms": ["Linux"],
        "procedure_examples": [],
        "tactics": [{"name": "initial-access", "id": "TA0001"}],
    }
    session = MagicMock()
    session.run = AsyncMock(return_value=AsyncRecords([record]))
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    client = MagicMock()
    client.embeddings.create = AsyncMock(
        return_value=MagicMock(
            data=[
                MagicMock(embedding=[1.0, 0.0]),
                MagicMock(embedding=[1.0, 0.0]),
            ]
        )
    )
    model = "multi-item-model"
    GraphRepository._description_embedding_cache[model] = {
        "T1190": (embedding_cache_key(record, model), [[1.0, 0.0]])
    }

    candidates = await GraphRepository(driver, client, model).description_attack_candidates(
        "CVE-2026-0004",
        {
            "exploitation_behaviors": ["Trigger path A", "Trigger path B"],
            "primary_capabilities": [],
            "secondary_behaviors": [],
        },
    )

    client.embeddings.create.assert_awaited_once()
    assert len(candidates["exploitation"]) == 1
    assert candidates["exploitation"][0].retrieved_by == [
        "exploitation_behaviors[0]",
        "exploitation_behaviors[1]",
    ]


@pytest.mark.asyncio
async def test_attack_candidates_are_semantically_reranked_without_platform_filter() -> None:
    session = MagicMock()
    session.run = AsyncMock(
        return_value=AsyncRecords(
            [
                {
                    "mitre_technique_id": "T1105",
                    "name": "Ingress Tool Transfer",
                    "description": "Transfer files from an external system.",
                    "platforms": ["Windows"],
                    "procedure_examples": [],
                    "tactics": [{"name": "command-and-control", "id": "TA0011"}],
                    "score": 2,
                    "primary_match": True,
                }
            ]
        )
    )
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    embedding_client = MagicMock()
    embedding_client.embeddings.create = AsyncMock(
        side_effect=[
            MagicMock(data=[MagicMock(embedding=[0.9, 0.1])]),
            MagicMock(data=[MagicMock(embedding=[1.0, 0.0])]),
        ]
    )
    embedding_client.chat.completions.create = AsyncMock(
        side_effect=[
            MagicMock(
                choices=[
                    MagicMock(
                        message=MagicMock(
                            content=(
                                '{"candidates":[{"mitre_technique_id":"T1105",'
                                '"reasoning":"The behavior transfers a file.","rerank_score":0.9}]}'
                            )
                        )
                    )
                ]
            )
        ]
    )
    step = ExploitStep.model_validate(
        {
            "step": 1,
            "action": "Download malicious archive",
            "outcome": "Archive reaches host",
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "The client downloads the archive.",
                }
            ],
        }
    )

    candidates = await GraphRepository(
        driver, embedding_client, "test-embedding-model"
    ).attack_candidates(step)

    assert candidates[0].mitre_technique_id == "T1105"
    query = session.run.await_args.args[0]
    assert "coalesce(technique.deprecated, false) = false" in query
    assert "coalesce(technique.revoked, false) = false" in query
    assert "OPTIONAL MATCH (technique)-[:HAS_TACTIC]" in query
    assert "technique.revoked = false" not in query
    assert "technique.platforms" not in query.split("RETURN")[0]
    assert "technique.procedure_examples" in query
    assert embedding_client.embeddings.create.await_count == 2
    embedding_request = embedding_client.embeddings.create.await_args_list[0].kwargs
    assert embedding_request["model"] == "test-embedding-model"
    assert len(embedding_request["input"]) == 1
    technique_document = embedding_request["input"][0]
    assert technique_document.startswith("MITRE ATT&CK Technique: T1105")
    assert "Tactics: command-and-control" in technique_document
    query_request = embedding_client.embeddings.create.await_args_list[1].kwargs
    assert query_request["input"] == [behavior_query(step)]
    assert embedding_client.chat.completions.create.await_count == 1


@pytest.mark.asyncio
async def test_attack_candidates_do_not_retry_invalid_reranker_response() -> None:
    session = MagicMock()
    session.run = AsyncMock(
        return_value=AsyncRecords(
            [
                {
                    "mitre_technique_id": "T1583.001",
                    "name": "Acquire Infrastructure: Domains",
                    "description": "Adversaries may acquire domains for targeting.",
                    "platforms": [],
                    "tactics": [{"name": "resource-development", "id": "TA0042"}],
                }
            ]
        )
    )
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    client = MagicMock()
    client.embeddings.create = AsyncMock(
        side_effect=[
            MagicMock(data=[MagicMock(embedding=[1.0, 0.0])]),
            MagicMock(data=[MagicMock(embedding=[1.0, 0.0])]),
        ]
    )
    client.chat.completions.create = AsyncMock(
        side_effect=[
            MagicMock(choices=[MagicMock(message=MagicMock(content="not json"))]),
            MagicMock(
                choices=[
                    MagicMock(
                        message=MagicMock(
                            content=(
                                '{"candidates":[{"mitre_technique_id":"T1583.001",'
                                '"reasoning":"The attacker acquires a domain.",'
                                '"rerank_score":0.95}]}'
                            )
                        )
                    )
                ]
            ),
        ]
    )
    item = ExploitStep.model_validate(
        {
            "step": 1,
            "action": "Register abandoned domain",
            "outcome": "Attacker controls the domain",
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "The abandoned domain was registered.",
                }
            ],
        }
    )

    candidates = await GraphRepository(driver, client, "embedding-model").attack_candidates(item)

    assert candidates[0].mitre_technique_id == "T1583.001"
    assert client.chat.completions.create.await_count == 1


@pytest.mark.asyncio
async def test_attack_candidates_fall_back_after_one_empty_rerank() -> None:
    session = MagicMock()
    session.run = AsyncMock(
        return_value=AsyncRecords(
            [
                {
                    "mitre_technique_id": "T1105",
                    "name": "Ingress Tool Transfer",
                    "description": "Transfer files from an external system.",
                    "platforms": ["Windows"],
                    "procedure_examples": [],
                    "revoked": False,
                    "tactics": [{"name": "command-and-control", "id": "TA0011"}],
                }
            ]
        )
    )
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    client = MagicMock()
    client.embeddings.create = AsyncMock(
        side_effect=[
            MagicMock(data=[MagicMock(embedding=[1.0, 0.0])]),
            MagicMock(data=[MagicMock(embedding=[1.0, 0.0])]),
        ]
    )
    empty = MagicMock(choices=[MagicMock(message=MagicMock(content=""))])
    client.chat.completions.create = AsyncMock(return_value=empty)
    item = ExploitStep.model_validate(
        {
            "step": 2,
            "action": "Download a malicious archive",
            "outcome": "The archive reaches the target",
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "The target downloads the malicious archive.",
                }
            ],
        }
    )

    candidates = await GraphRepository(driver, client, "embedding-model").attack_candidates(item)

    assert [item.mitre_technique_id for item in candidates] == ["T1105"]
    assert client.chat.completions.create.await_count == 1


@pytest.mark.asyncio
async def test_attack_candidates_embed_raw_query_without_normalization() -> None:
    session = MagicMock()
    session.run = AsyncMock(
        return_value=AsyncRecords(
            [
                {
                    "mitre_technique_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "description": "Exploit a weakness in an Internet-facing host.",
                    "platforms": ["Network Devices"],
                    "tactics": [{"name": "initial-access", "id": "TA0001"}],
                }
            ]
        )
    )
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    client = MagicMock()
    client.embeddings.create = AsyncMock(
        side_effect=[
            MagicMock(data=[MagicMock(embedding=[1.0, 0.0])]),
            MagicMock(data=[MagicMock(embedding=[1.0, 0.0])]),
        ]
    )
    reranked = MagicMock(
        choices=[
            MagicMock(
                message=MagicMock(
                    content=(
                        '{"candidates":[{"mitre_technique_id":"T1190",'
                        '"reasoning":"The behavior exploits an exposed application.",'
                        '"rerank_score":0.95}]}'
                    )
                )
            )
        ]
    )
    client.chat.completions.create = AsyncMock(return_value=reranked)
    item = ExploitStep.model_validate(
        {
            "step": 3,
            "action": "Send an oversized request to the VPN gateway",
            "outcome": "Remote code execution",
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "The crafted request triggers a buffer overflow.",
                }
            ],
        }
    )

    candidates = await GraphRepository(driver, client, "embedding-model").attack_candidates(item)

    raw_query = behavior_query(item)
    query_request = client.embeddings.create.await_args_list[1].kwargs
    assert query_request["input"] == [raw_query]
    assert candidates[0].mitre_technique_id == "T1190"
    assert client.chat.completions.create.await_count == 1
