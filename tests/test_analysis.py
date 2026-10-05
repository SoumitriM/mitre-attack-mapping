from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.analysis import CVEAnalysisService
from app.config import Settings
from app.enrichment.ctid_mapper import CTIDMappingError
from app.models import (
    CVERecord,
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
async def test_ctid_failure_is_explicitly_logged_and_reported(caplog, monkeypatch) -> None:
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
    monkeypatch.setattr("app.analysis.CVEIngestionService.analyze", AsyncMock(return_value=cve))
    graph = MagicMock()
    graph.verify_taxonomy = AsyncMock()
    graph.attack_candidates = AsyncMock(return_value=[])
    mapper = MagicMock(model="mapper-model")
    mapper.map_steps = AsyncMock(return_value=[])
    ctid_mapper = MagicMock(model="ctid-model")
    ctid_mapper.map = AsyncMock(side_effect=CTIDMappingError("contract mismatch"))
    agent = MagicMock(model="extractor-model")
    agent.extract = AsyncMock(return_value=[step()])
    service = CVEAnalysisService(
        Settings(enable_ctid_mapping=True),
        graph,
        MagicMock(),
        agent,
        mapper,
        ctid_mapper,
    )

    with caplog.at_level("ERROR"):
        result = await service.analyze(cve.cve_id, description_source="advisories")

    assert result.cve_level_attack_mappings.exploitation_techniques == []
    assert "CVE-level CTID mapping failed: contract mismatch" in result.warnings
    assert "CVE-level CTID mapping failed" in caplog.text


@pytest.mark.asyncio
async def test_request_data_is_not_read_from_or_written_to_neo4j(caplog, monkeypatch) -> None:
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
    monkeypatch.setattr("app.analysis.CVEIngestionService.analyze", AsyncMock(return_value=cve))
    graph = MagicMock()
    graph.verify_taxonomy = AsyncMock()
    graph.cached_cve = AsyncMock()
    graph.cached_steps = AsyncMock()
    graph.replace_analysis = AsyncMock()
    graph.attack_candidates = AsyncMock(return_value=[])
    graph.replace_attack_mappings = AsyncMock()
    graph.replace_validated_attack_chain = AsyncMock()
    graph.replace_cve_level_attack_mappings = AsyncMock()
    mapper = MagicMock(model="mapper-model")
    mapper.map_steps = AsyncMock(return_value=[])
    ctid_mapper = MagicMock(model="ctid-model")
    ctid_mapper.map = AsyncMock()
    agent = MagicMock(model="extractor-model")
    agent.extract = AsyncMock(return_value=[step()])
    service = CVEAnalysisService(
        Settings(enable_ctid_mapping=False),
        graph,
        MagicMock(),
        agent,
        mapper,
        ctid_mapper,
    )

    with caplog.at_level("INFO"):
        result = await service.analyze(cve.cve_id, description_source="advisories")

    ctid_mapper.map.assert_not_awaited()
    graph.cached_cve.assert_not_awaited()
    graph.cached_steps.assert_not_awaited()
    agent.extract.assert_awaited_once()
    graph.replace_analysis.assert_not_awaited()
    graph.replace_attack_mappings.assert_not_awaited()
    graph.replace_validated_attack_chain.assert_not_awaited()
    graph.replace_cve_level_attack_mappings.assert_not_awaited()
    assert result.cve_level_attack_mappings.exploitation_techniques == []
    assert "CTID mapping skipped" in caplog.text
