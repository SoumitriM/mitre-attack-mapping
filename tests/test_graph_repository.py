from collections.abc import AsyncIterator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.graph.repository import GraphRepository
from app.models import (
    AttackMapping,
    CVERecord,
    ExploitStep,
    SourceAttribution,
    ValidatedAttackStep,
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
async def test_attack_candidates_are_bounded_and_platform_filtered() -> None:
    session = MagicMock()
    session.run = AsyncMock(return_value=AsyncRecords([{
        "mitre_technique_id": "T1105",
        "name": "Ingress Tool Transfer",
        "description": "Transfer files from an external system.",
        "platforms": ["Windows"],
        "tactics": [{"name": "command-and-control", "id": "TA0011"}],
    }]))
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    step = ExploitStep.model_validate({
        "step": 1,
        "action": "Download malicious archive",
        "outcome": "Archive reaches host",
        "evidence": [{
            "source_url": "https://research.example/advisory",
            "supporting_text": "The client downloads the archive.",
        }],
    })

    candidates = await GraphRepository(driver).attack_candidates(step, ["Windows"])

    assert candidates[0].mitre_technique_id == "T1105"
    parameters = session.run.await_args.kwargs
    assert parameters["platforms"] == ["windows"]
    assert parameters["limit"] == 8
    assert "download" in parameters["tokens"]


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
    session.run = AsyncMock(return_value=AsyncRecords([{
        "mitre_technique_id": "T1105",
        "name": "Ingress Tool Transfer",
        "description": "Transfer files from an external system.",
        "platforms": ["Windows"],
        "tactics": [{"name": "command-and-control", "id": "TA0011"}],
    }]))
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
            mitre_technique_id="T1105",
            mitre_tactic_id="TA0011",
            reasoning="The evidence supports file transfer.",
            confidence=0.9,
            evidence_ids=["evidence-1"],
            validation_status=ValidationStatus.VALIDATED,
        ),
        ValidatedAttackStep(
            step=2,
            action="Launch updater",
            reasoning="No evidenced ATT&CK behavior was established.",
            confidence=0.1,
            validation_status=ValidationStatus.UNMAPPED,
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
    assert "item.validation_status <> 'validated'" in query
    assert "edge.validation_model = $validation_model" in query
    assert parameters["chain"][1]["mitre_technique_id"] is None
