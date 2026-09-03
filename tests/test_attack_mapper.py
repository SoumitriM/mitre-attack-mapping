from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.config import Settings
from app.enrichment.attack_mapper import (
    FHGenieAttackMapper,
    evidence_id,
)
from app.models import AffectedProduct, AttackCandidate, CVERecord, ExploitStep


def response(content: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def cve() -> CVERecord:
    return CVERecord(
        cve_id="CVE-2026-22306",
        affected_products=[AffectedProduct(product="OZOLS", platforms=["Windows"])],
        cwe_ids=["CWE-494"],
        capec_ids=["CAPEC-187"],
    )


def step() -> ExploitStep:
    return ExploitStep.model_validate({
        "step": 1,
        "action": "Download malicious archive",
        "prerequisites": ["Update endpoint is controlled"],
        "outcome": "Archive reaches the Windows host",
        "evidence": [{
            "source_url": "https://research.example/advisory",
            "supporting_text": "The client downloads the malicious archive.",
        }],
    })


def candidate(platforms: list[str] | None = None) -> AttackCandidate:
    return AttackCandidate(
        mitre_technique_id="T1105",
        name="Ingress Tool Transfer",
        description="Adversaries may transfer tools or files from an external system.",
        platforms=platforms or ["Windows"],
        tactics={"command-and-control": "TA0011"},
    )


def settings() -> Settings:
    return Settings(_env_file=None, fh_genie_model="test-model")


@pytest.mark.asyncio
async def test_accepts_only_supplied_platform_compatible_candidate() -> None:
    item = step()
    ev_id = evidence_id(str(item.evidence[0].source_url), item.evidence[0].supporting_text)
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response(
        '{"mappings":[{"step":1,"action":"Download malicious archive",'
        '"mitre_technique_id":"T1105","mitre_tactic_id":"TA0011",'
        '"reasoning":"The archive is transferred to the target.","confidence":0.91,'
        f'"evidence_ids":["{ev_id}"]}}]}}'
    ))

    mappings = await FHGenieAttackMapper(settings(), api).map_steps(
        cve(), [item], {1: [candidate()]}
    )

    assert mappings[0].mitre_technique_id == "T1105"
    assert mappings[0].mitre_tactic_id == "TA0011"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("technique", "tactic", "platforms"),
    [("T9999", "TA0011", ["Windows"]), ("T1105", "TA9999", ["Windows"]),
     ("T1105", "TA0011", ["Linux"])],
)
async def test_rejects_candidate_tactic_or_platform_outside_official_set(
    technique: str, tactic: str, platforms: list[str]
) -> None:
    item = step()
    ev_id = evidence_id(str(item.evidence[0].source_url), item.evidence[0].supporting_text)
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response(
        '{"mappings":[{"step":1,"action":"Download malicious archive",'
        f'"mitre_technique_id":"{technique}","mitre_tactic_id":"{tactic}",'
        '"reasoning":"Claim","confidence":0.9,'
        f'"evidence_ids":["{ev_id}"]}}]}}'
    ))

    mappings = await FHGenieAttackMapper(settings(), api).map_steps(
        cve(), [item], {1: [candidate(platforms)]}
    )

    assert mappings[0].mitre_technique_id is None
    assert "deterministic validation" in mappings[0].reasoning


@pytest.mark.asyncio
async def test_accepts_explicit_low_confidence_no_match() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response(
        '{"mappings":[{"step":1,"action":"Download malicious archive",'
        '"mitre_technique_id":null,"mitre_tactic_id":null,'
        '"reasoning":"No candidate fits.","confidence":0.2,"evidence_ids":[]}]}'
    ))

    mappings = await FHGenieAttackMapper(settings(), api).map_steps(cve(), [step()], {1: []})

    assert mappings[0].mitre_technique_id is None
