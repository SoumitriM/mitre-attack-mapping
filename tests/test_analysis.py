from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.analysis import CVEAnalysisService
from app.config import Settings
from app.enrichment.ctid_mapper import CTIDMappingError, CTIDNormalizedSemantics
from app.models import (
    CVELevelAttackMappings,
    CVERecord,
    EvidenceSubgraph,
    ExploitStep,
    SourceAttribution,
)


def step() -> ExploitStep:
    return ExploitStep.model_validate(
        {
            "step": 1,
            "action": "Trigger a stack-based buffer overflow",
            "outcome": "Remote code execution",
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "The overflow permits remote code execution.",
                }
            ],
        }
    )


@pytest.mark.asyncio
async def test_ctid_failure_is_explicitly_logged_and_reported(caplog) -> None:
    cve = CVERecord(
        cve_id="CVE-2025-0282",
        description="Evidence-backed description",
        sources=[
            SourceAttribution(
                name="NVD",
                url="https://nvd.nist.gov/vuln/detail/CVE-2025-0282",
                retrieved_at=datetime.now(UTC),
            )
        ],
        field_provenance={"description": ["NVD"]},
    )
    graph = MagicMock()
    graph.verify_taxonomy = AsyncMock()
    graph.cached_cve = AsyncMock(return_value=cve)
    graph.cached_steps = AsyncMock(return_value=[step()])
    graph.replace_analysis = AsyncMock()
    graph.attack_candidates = AsyncMock(return_value=[])
    graph.replace_attack_mappings = AsyncMock()
    graph.replace_validated_attack_chain = AsyncMock()
    graph.replace_cve_level_attack_mappings = AsyncMock()
    graph.subgraph = AsyncMock(return_value=EvidenceSubgraph())
    mapper = MagicMock(model="mapper-model")
    mapper.map_steps = AsyncMock(return_value=[])
    validator = MagicMock(model="validator-model")
    validator.validate = AsyncMock()
    ctid_mapper = MagicMock(model="ctid-model")
    ctid_mapper.map = AsyncMock(side_effect=CTIDMappingError("contract mismatch"))
    agent = MagicMock(model="extractor-model")
    agent.extract = AsyncMock(return_value=[step()])
    service = CVEAnalysisService(
        Settings(enable_ctid_mapping=True, ctid_only_mode=False),
        graph,
        MagicMock(),
        agent,
        mapper,
        validator,
        ctid_mapper,
    )

    with caplog.at_level("ERROR"):
        result = await service.analyze(cve.cve_id)

    assert result.cve_level_attack_mappings.exploitation_techniques == []
    assert "CVE-level CTID mapping failed: contract mismatch" in result.warnings
    assert "CVE-level CTID mapping failed" in caplog.text
    validator.validate.assert_not_awaited()


@pytest.mark.asyncio
async def test_ctid_is_skipped_by_default_without_mapper_or_persistence_calls(caplog) -> None:
    cve = CVERecord(
        cve_id="CVE-2025-0282",
        description="Evidence-backed description",
        sources=[
            SourceAttribution(
                name="NVD",
                url="https://nvd.nist.gov/vuln/detail/CVE-2025-0282",
                retrieved_at=datetime.now(UTC),
            )
        ],
        field_provenance={"description": ["NVD"]},
    )
    graph = MagicMock()
    graph.verify_taxonomy = AsyncMock()
    graph.cached_cve = AsyncMock(return_value=cve)
    graph.cached_steps = AsyncMock(return_value=[step()])
    graph.replace_analysis = AsyncMock()
    graph.attack_candidates = AsyncMock(return_value=[])
    graph.replace_attack_mappings = AsyncMock()
    graph.replace_validated_attack_chain = AsyncMock()
    graph.replace_cve_level_attack_mappings = AsyncMock()
    graph.subgraph = AsyncMock(return_value=EvidenceSubgraph())
    mapper = MagicMock(model="mapper-model")
    mapper.map_steps = AsyncMock(return_value=[])
    validator = MagicMock(model="validator-model")
    validator.validate = AsyncMock()
    ctid_mapper = MagicMock(model="ctid-model")
    ctid_mapper.map = AsyncMock()
    agent = MagicMock(model="extractor-model")
    agent.extract = AsyncMock(return_value=[step()])
    service = CVEAnalysisService(
        Settings(ctid_only_mode=False),
        graph,
        MagicMock(),
        agent,
        mapper,
        validator,
        ctid_mapper,
    )

    with caplog.at_level("INFO"):
        result = await service.analyze(cve.cve_id)

    ctid_mapper.map.assert_not_awaited()
    graph.cached_steps.assert_not_awaited()
    agent.extract.assert_awaited_once()
    graph.replace_cve_level_attack_mappings.assert_not_awaited()
    assert result.cve_level_attack_mappings.exploitation_techniques == []
    assert "CTID mapping skipped" in caplog.text
    validator.validate.assert_not_awaited()


@pytest.mark.asyncio
async def test_ctid_only_mode_bypasses_detailed_attack_chain() -> None:
    cve = CVERecord(
        cve_id="CVE-2026-9323",
        description="A predictable session identifier permits session access.",
    )
    graph = MagicMock()
    graph.verify_taxonomy = AsyncMock()
    graph.cached_cve = AsyncMock(return_value=cve)
    graph.description_attack_candidates = AsyncMock(
        return_value={"exploitation": [], "primary_impact": [], "secondary_impact": []}
    )
    graph.replace_cve_level_attack_mappings = AsyncMock()
    graph.attack_candidates = AsyncMock()
    agent = MagicMock(model="extractor-model")
    agent.extract = AsyncMock()
    mapper = MagicMock(model="mapper-model")
    mapper.map_steps = AsyncMock()
    validator = MagicMock(model="validator-model")
    validator.validate = AsyncMock()
    ctid_mapper = MagicMock(model="ctid-model")
    normalized = CTIDNormalizedSemantics(
        exploitation_behaviors=["Exploit a predictable session identifier"],
        primary_capabilities=["Gain control of a victim session"],
        secondary_behaviors=[],
    )
    ctid_mapper.normalize_description = AsyncMock(return_value=normalized)
    ctid_mapper.map_description = AsyncMock(return_value=CVELevelAttackMappings())
    service = CVEAnalysisService(
        Settings(ctid_only_mode=True),
        graph,
        MagicMock(),
        agent,
        mapper,
        validator,
        ctid_mapper,
    )

    result = await service.analyze(cve.cve_id)

    ctid_mapper.normalize_description.assert_awaited_once_with(cve)
    graph.description_attack_candidates.assert_awaited_once_with(
        cve.cve_id, normalized.model_dump(mode="json")
    )
    ctid_mapper.map_description.assert_awaited_once()
    agent.extract.assert_not_awaited()
    graph.attack_candidates.assert_not_awaited()
    mapper.map_steps.assert_not_awaited()
    validator.validate.assert_not_awaited()
    assert result.exploit_steps == []
    assert result.attack_chain == []
