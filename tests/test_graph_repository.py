from collections.abc import AsyncIterator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.enrichment.candidate_retrieval import behavior_query
from app.graph.repository import GraphRepository
from app.models import (
    AttackMapping,
    CVERecord,
    ExploitStep,
    SourceAttribution,
    ValidatedAttackStep,
    ValidationChecks,
    ValidationDetails,
    ValidationStatus,
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
async def test_graph_upsert_uses_cve_id_parameter() -> None:
    result = MagicMock()
    result.consume = AsyncMock()
    session = MagicMock()
    session.run = AsyncMock(return_value=result)
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    record = CVERecord(
        cve_id="CVE-2026-22306",
        sources=[
            SourceAttribution(
                name="NVD",
                url="https://nvd.nist.gov/vuln/detail/CVE-2026-22306",
                retrieved_at=datetime.now(UTC),
            )
        ],
    )

    await GraphRepository(driver).replace_analysis(
        record,
        [],
        [],
        cache_key="cache",
        model="model",
        prompt_version="v1",
    )

    query = session.run.await_args.args[0]
    parameters = session.run.await_args.kwargs
    assert "MERGE (cve:CVE {id: $cve.cve_id})" in query
    assert parameters["cve"]["cve_id"] == "CVE-2026-22306"
    assert parameters["record_json"] == record.model_dump_json()
    assert parameters["retrieved_at"] == record.sources[0].retrieved_at.isoformat()


@pytest.mark.asyncio
async def test_cve_cache_returns_fresh_normalized_record() -> None:
    cached = CVERecord(cve_id="CVE-2026-22306", description="cached")
    result = MagicMock()
    result.single = AsyncMock(return_value={"record_json": cached.model_dump_json()})
    session = MagicMock()
    session.run = AsyncMock(return_value=result)
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context

    record = await GraphRepository(driver).cached_cve("CVE-2026-22306", 3600)

    assert record == cached
    parameters = session.run.await_args.kwargs
    assert parameters["cve_id"] == "CVE-2026-22306"
    assert "cutoff" in parameters


@pytest.mark.asyncio
async def test_zero_ttl_always_bypasses_cve_cache() -> None:
    driver = MagicMock()

    record = await GraphRepository(driver).cached_cve("CVE-2026-22306", 0)

    assert record is None
    driver.session.assert_not_called()


@pytest.mark.asyncio
async def test_subgraph_does_not_traverse_back_into_cves_sharing_a_weakness() -> None:
    result = MagicMock()
    result.single = AsyncMock(return_value=None)
    session = MagicMock()
    session.run = AsyncMock(return_value=result)
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context

    subgraph = await GraphRepository(driver).subgraph("CVE-2026-63077")

    assert subgraph.nodes == []
    query = session.run.await_args.args[0]
    assert "-[*0..3]->(node)" in query
    assert "-[*0..3]-(node)" not in query
    assert session.run.await_args.kwargs == {"cve_id": "CVE-2026-63077"}


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
            MagicMock(choices=[MagicMock(message=MagicMock(content=(
                '{"normalized_query":"Transfer a malicious file from an external system."}'
            )))]),
            MagicMock(
                choices=[MagicMock(message=MagicMock(content=(
                    '{"candidates":[{"mitre_technique_id":"T1105",'
                    '"reasoning":"The behavior transfers a file.","rerank_score":0.9}]}'
                )))]
            ),
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
    ).attack_candidates(step, ["Windows"])

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
    assert query_request["input"] == [
        "Transfer a malicious file from an external system."
    ]
    assert embedding_client.chat.completions.create.await_count == 2


@pytest.mark.asyncio
async def test_attack_candidates_retry_invalid_reranker_response() -> None:
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
            MagicMock(choices=[MagicMock(message=MagicMock(content=(
                '{"normalized_query":"Acquire infrastructure by registering a domain."}'
            )))]),
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

    candidates = await GraphRepository(driver, client, "embedding-model").attack_candidates(
        item, []
    )

    assert candidates[0].mitre_technique_id == "T1583.001"
    assert client.chat.completions.create.await_count == 3


@pytest.mark.asyncio
async def test_attack_candidates_fall_back_to_raw_query_when_normalization_is_empty() -> None:
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
    empty = MagicMock(choices=[MagicMock(message=MagicMock(content=""))])
    reranked = MagicMock(choices=[MagicMock(message=MagicMock(content=(
        '{"candidates":[{"mitre_technique_id":"T1190",'
        '"reasoning":"The behavior exploits an exposed application.",'
        '"rerank_score":0.95}]}'
    )))])
    client.chat.completions.create = AsyncMock(side_effect=[empty, empty, reranked])
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

    candidates = await GraphRepository(driver, client, "embedding-model").attack_candidates(
        item, ["Network Devices"]
    )

    raw_query = behavior_query(item)
    query_request = client.embeddings.create.await_args_list[1].kwargs
    assert query_request["input"] == [raw_query]
    assert candidates[0].mitre_technique_id == "T1190"
    assert client.chat.completions.create.await_count == 3


@pytest.mark.asyncio
async def test_mapping_edge_records_model_prompt_reasoning_and_confidence() -> None:
    result = MagicMock()
    result.consume = AsyncMock()
    session = MagicMock()
    session.run = AsyncMock(return_value=result)
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    mapping = AttackMapping(
        step=4,
        action="Serve malicious archive",
        mitre_technique_id="T1105",
        mitre_tactic_id="TA0011",
        reasoning="The archive is transferred to the target.",
        confidence=0.91,
        evidence_ids=["evidence-1"],
    )

    await GraphRepository(driver).replace_attack_mappings(
        "CVE-2026-22306",
        [mapping],
        model="fh-model",
        prompt_version="attack-mapping-v1",
    )

    query = session.run.await_args.args[0]
    parameters = session.run.await_args.kwargs
    assert "[edge:MAPS_TO]" in query
    assert "edge.reasoning = mapping.reasoning" in query
    assert parameters["model"] == "fh-model"
    assert parameters["mappings"][0]["confidence"] == 0.91


@pytest.mark.asyncio
async def test_official_attack_context_excludes_unavailable_techniques() -> None:
    session = MagicMock()
    session.run = AsyncMock(
        return_value=AsyncRecords(
            [
                {
                    "mitre_technique_id": "T1105",
                    "name": "Ingress Tool Transfer",
                    "description": "Transfer files from an external system.",
                    "platforms": ["Windows"],
                    "tactics": [{"name": "command-and-control", "id": "TA0011"}],
                }
            ]
        )
    )
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context

    official = await GraphRepository(driver).official_attack_context(["T9999", "T1105"])

    assert list(official) == ["T1105"]
    assert official["T1105"].tactics == {"command-and-control": "TA0011"}
    query = session.run.await_args.args[0]
    assert "technique.revoked = false" in query
    assert "technique.deprecated = false" in query


@pytest.mark.asyncio
async def test_validation_facts_find_tactic_and_linked_evidence() -> None:
    session = MagicMock()
    session.run = AsyncMock(
        return_value=AsyncRecords(
            [
                {
                    "step": 1,
                    "technique_lookup_found": True,
                    "technique_name": "Exploit Public-Facing Application",
                    "technique_platforms": ["Linux", "Windows"],
                    "tactic_relationship_found": True,
                    "linked_ids": ["evidence-1"],
                    "node_ids": ["evidence-1"],
                    "empty_text_ids": [],
                }
            ]
        )
    )
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    mapping = AttackMapping(
        step=1,
        action="Exploit the public-facing service",
        mitre_technique_id="T1190",
        mitre_tactic_id="TA0001",
        reasoning="The service is exploited remotely.",
        confidence=0.9,
        evidence_ids=["evidence-1"],
    )

    facts = await GraphRepository(driver).validation_facts("CVE-2025-0282", [mapping], [])

    assert facts[1]["technique_lookup_found"] is True
    assert facts[1]["tactic_relationship_found"] is True
    assert facts[1]["evidence_ids_found"] is True
    assert facts[1]["cve_platforms"] == []
    query = session.run.await_args.args[0]
    assert "(technique:AttackTechnique {id: mapping.mitre_technique_id})" in query
    assert "[:HAS_TACTIC]" in query
    assert "[:SUPPORTED_BY]" in query


@pytest.mark.asyncio
async def test_validated_chain_replaces_edges_and_stores_only_validated_items() -> None:
    result = MagicMock()
    result.consume = AsyncMock()
    session = MagicMock()
    session.run = AsyncMock(return_value=result)
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    chain = [
        ValidatedAttackStep(
            step=1,
            action="Download malicious archive",
            proposed_technique_id="T1105",
            mitre_tactic_id="TA0011",
            evidence_ids=["evidence-1"],
            validation=ValidationDetails(
                status=ValidationStatus.VALIDATED,
                checks=ValidationChecks(
                    technique_exists=True,
                    tactic_valid=True,
                    platform_compatible=True,
                    evidence_support=True,
                    semantic_match=True,
                ),
                reasoning="The evidence supports file transfer.",
                validator_confidence=0.9,
            ),
        ),
        ValidatedAttackStep(
            step=2,
            action="Launch updater",
            evidence_ids=[],
            validation=ValidationDetails(
                status=ValidationStatus.UNMAPPED,
                checks=ValidationChecks(
                    technique_exists=False,
                    tactic_valid=False,
                    platform_compatible=False,
                    evidence_support=False,
                    semantic_match=False,
                ),
                reasoning="No evidenced ATT&CK behavior was established.",
                validator_confidence=0.1,
            ),
        ),
    ]

    await GraphRepository(driver).replace_validated_attack_chain(
        "CVE-2026-22306",
        chain,
        mapping_model="mapper",
        mapping_prompt_version="mapping-v1",
        validation_model="validator",
        validation_prompt_version="validation-v1",
    )

    query = session.run.await_args.args[0]
    parameters = session.run.await_args.kwargs
    assert "DELETE old" in query
    assert "item.validation.status <> 'validated'" in query
    assert "edge.validation_model = $validation_model" in query
    assert parameters["chain"][1]["proposed_technique_id"] is None


@pytest.mark.asyncio
async def test_presentation_graph_exposes_provenance_and_step_details() -> None:
    context_result = MagicMock()
    context_result.single = AsyncMock(
        return_value={
            "description": "Example vulnerability",
            "cwes": [{"id": "CWE-494", "name": "Download without integrity check"}],
            "capecs": [{"id": "CAPEC-187", "name": "Malicious update"}],
        }
    )
    steps_result = AsyncRecords(
        [
            {
                "id": "CVE-2026-22306:1",
                "step": 1,
                "action": "Download malicious archive",
                "prerequisites": ["Update check"],
                "outcome": "Archive reaches host",
                "evidence": [
                    {
                        "id": "evidence-1",
                        "source_url": "https://research.example/advisory",
                        "supporting_text": "The client downloads the archive.",
                    }
                ],
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic_id": "TA0011",
                "tactic_name": "Command and Control",
                "reasoning": "The evidence supports transfer.",
                "confidence": 0.9,
                "evidence_ids": ["evidence-1"],
                "validation_status": "validated",
            }
        ]
    )
    session = MagicMock()
    session.run = AsyncMock(side_effect=[context_result, steps_result])
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context

    graph = await GraphRepository(driver).validated_attack_chain_graph("CVE-2026-22306")

    assert graph is not None
    step_node = next(node for node in graph.nodes if node.type == "exploit_step")
    assert step_node.provenance == "advisory_derived"
    assert step_node.properties["mitre_technique_id"] == "T1105"
    assert step_node.properties["evidence_sources"] == ["https://research.example/advisory"]
    mapping_edge = next(edge for edge in graph.edges if edge.relationship == "MAPS_TO")
    assert mapping_edge.provenance == "llm_inferred"
    assert mapping_edge.properties["validation_status"] == "validated"
    assert any(edge.relationship == "HAS_TACTIC" for edge in graph.edges)
