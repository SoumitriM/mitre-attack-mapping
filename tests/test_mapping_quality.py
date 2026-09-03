"""Tests for false-positive ATT&CK mapping patterns and quality improvements."""

import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.config import Settings
from app.enrichment.attack_mapper import FHGenieAttackMapper
from app.models import (
    AffectedProduct,
    AttackCandidate,
    AttackMapping,
    CVERecord,
    CVSSMetrics,
    ExploitStep,
)


def response(content: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def cve() -> CVERecord:
    return CVERecord(
        cve_id="CVE-2026-22306",
        affected_products=[AffectedProduct(product="OZOLS", platforms=["Windows"])],
        cvss=CVSSMetrics(version="3.1", attack_vector="NETWORK", user_interaction="REQUIRED"),
        cwe_ids=["CWE-494"],
        capec_ids=["CAPEC-187"],
    )


def step(
    number: int = 1,
    action: str = "Download update archive",
    outcome: str = "Archive reaches host",
) -> ExploitStep:
    return ExploitStep.model_validate(
        {
            "step": number,
            "action": action,
            "outcome": outcome,
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "The client downloads an archive.",
                }
            ],
        }
    )


def candidate_t1027() -> AttackCandidate:
    """T1027: Obfuscated Files or Information - requires hiding intent/nature."""
    return AttackCandidate(
        mitre_technique_id="T1027",
        name="Obfuscated Files or Information",
        description=(
            "Adversaries may attempt to make an executable or file difficult to "
            "discover or analyze by obfuscating its contents."
        ),
        platforms=["Windows", "Linux", "macOS"],
        tactics={"defense-evasion": "TA0005"},
    )


def candidate_t1189() -> AttackCandidate:
    """T1189: Drive-by Compromise - requires malicious website + automatic exploit."""
    return AttackCandidate(
        mitre_technique_id="T1189",
        name="Drive-by Compromise",
        description=(
            "Adversaries may gain access to a system through a user visiting a website "
            "over the normal course of browsing. With this technique, the user's web "
            "browser is typically targeted for exploitation."
        ),
        platforms=["Windows", "Linux", "macOS"],
        tactics={"initial-access": "TA0001"},
    )


def candidate_t1053() -> AttackCandidate:
    """T1053: Scheduled Task/Job - requires actual task scheduling mechanism."""
    return AttackCandidate(
        mitre_technique_id="T1053",
        name="Scheduled Task/Job",
        description=(
            "Adversaries may abuse task scheduling functionality to facilitate initial "
            "or recurring execution of malicious code."
        ),
        platforms=["Windows", "Linux", "macOS"],
        tactics={"execution": "TA0002", "persistence": "TA0003"},
    )


def candidate_t1105() -> AttackCandidate:
    """T1105: Ingress Tool Transfer - requires actual file transfer behavior."""
    return AttackCandidate(
        mitre_technique_id="T1105",
        name="Ingress Tool Transfer",
        description=(
            "Adversaries may transfer files from an external system into a compromised "
            "environment as part of the ingress process."
        ),
        platforms=["Windows", "Linux", "macOS"],
        tactics={"command-and-control": "TA0011"},
    )


def settings() -> Settings:
    return Settings(_env_file=None, fh_genie_model="test-model", mapping_min_confidence=0.75)


def evidence_id(source_url: str, supporting_text: str) -> str:
    return hashlib.sha256(f"{source_url}\0{supporting_text}".encode()).hexdigest()


@pytest.mark.asyncio
async def test_rejects_archive_alone_without_obfuscation_for_t1027() -> None:
    """Archive presence alone does not prove T1027 (obfuscation) behavior."""
    item = step(
        action="Download update archive",
        outcome="Archive downloaded to disk",
    )
    api = MagicMock()
    # LLM proposes T1027 just because archive is mentioned
    # But confidence is low and violates minimum threshold
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"mappings":[{"step":1,"action":"Download update archive",'
            '"mitre_technique_id":null,"mitre_tactic_id":null,'
            '"reasoning":"Archive alone does not prove obfuscation behavior.","confidence":0.25,'
            '"evidence_ids":[]}]}'
        )
    )

    mappings = await FHGenieAttackMapper(settings(), api).map_steps(
        cve(), [item], {1: [candidate_t1027()]}
    )

    # LLM correctly identified this as not actually T1027
    assert mappings[0].mitre_technique_id is None
    assert mappings[0].confidence <= 0.33


@pytest.mark.asyncio
async def test_rejects_generic_server_for_t1189_without_exploit() -> None:
    """Generic attacker-controlled server does not prove T1189 (drive-by)."""
    item = step(
        action="Serve fake version file from attacker server",
        outcome="Victim connects to attacker server",
    )
    api = MagicMock()
    # LLM proposes T1189 but then correctly rejects it
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"mappings":[{"step":1,"action":"Serve fake version file from attacker server",'
            '"mitre_technique_id":null,"mitre_tactic_id":null,'
            '"reasoning":"Generic server presence does not imply drive-by compromise '
            'behavior. Drive-by requires automatic exploitation.","confidence":0.20,'
            '"evidence_ids":[]}]}'
        )
    )

    mappings = await FHGenieAttackMapper(settings(), api).map_steps(
        cve(), [item], {1: [candidate_t1189()]}
    )

    # LLM correctly identified this as not T1189
    assert mappings[0].mitre_technique_id is None
    assert mappings[0].confidence <= 0.33


@pytest.mark.asyncio
async def test_allows_unmapped_exploit_specific_behavior() -> None:
    """Exploit-specific update mechanics can remain unmapped."""
    item = step(
        action="Increment version number in Vers.txt",
        outcome="Update mechanism checks version and installs archive",
    )
    api = MagicMock()
    # LLM correctly identifies this as exploit-specific, returns null
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"mappings":[{"step":1,"action":"Increment version number in Vers.txt",'
            '"mitre_technique_id":null,"mitre_tactic_id":null,'
            '"reasoning":"This is exploit-specific implementation logic and does not '
            'match official ATT&CK behavior.",'
            '"confidence":0.15,"evidence_ids":[]}]}'
        )
    )

    # Should succeed with null mapping
    mappings = await FHGenieAttackMapper(settings(), api).map_steps(
        cve(),
        [item],
        {1: []},  # No candidates for this step
    )

    assert mappings[0].mitre_technique_id is None
    assert mappings[0].confidence <= 0.33


@pytest.mark.asyncio
async def test_accepts_direct_file_transfer_match_for_t1105() -> None:
    """Actual file transfer behavior correctly maps to T1105."""
    item = step(
        action="Download malicious archive from attacker server",
        outcome="Exploit archive reaches target host",
    )
    # Calculate the correct evidence_id from step evidence
    eid = evidence_id("https://research.example/advisory", "The client downloads an archive.")

    api = MagicMock()
    # LLM correctly identifies T1105 with strong evidence
    api.chat.completions.create = AsyncMock(
        return_value=response(
            f'{{"mappings":[{{"step":1,"action":"Download malicious archive from attacker server",'
            f'"mitre_technique_id":"T1105","mitre_tactic_id":"TA0011",'
            f'"reasoning":"The observed behavior directly matches T1105: the malicious '
            f'file is transferred from external attacker infrastructure to the target host.",'
            f'"confidence":0.92,"evidence_ids":["{eid}"]}}]}}'
        )
    )

    # Should succeed with high confidence mapping
    mappings = await FHGenieAttackMapper(settings(), api).map_steps(
        cve(), [item], {1: [candidate_t1105()]}
    )

    assert mappings[0].mitre_technique_id == "T1105"
    assert mappings[0].confidence >= 0.75


@pytest.mark.asyncio
async def test_rejects_low_confidence_mapping_below_threshold() -> None:
    """Low confidence mappings (below 0.75) are rejected for quality."""
    item = step()
    api = MagicMock()
    # LLM returns low confidence mapping - should be unmapped instead
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"mappings":[{"step":1,"action":"Download update archive",'
            '"mitre_technique_id":null,"mitre_tactic_id":null,'
            '"reasoning":"Confidence is too low to warrant technique assignment.",'
            '"confidence":0.25,'
            '"evidence_ids":[]}]}'
        )
    )

    mappings = await FHGenieAttackMapper(settings(), api).map_steps(
        cve(), [item], {1: [candidate_t1105()]}
    )

    # Should correctly result in null mapping for low confidence
    assert mappings[0].mitre_technique_id is None
    assert mappings[0].confidence <= 0.33


@pytest.mark.asyncio
async def test_enforces_minimum_threshold_in_validator() -> None:
    """Mapper enforces strict quality threshold via _valid method."""
    mapper = FHGenieAttackMapper(settings(), MagicMock())

    # High confidence, valid mapping should pass
    strong_mapping = [
        AttackMapping(
            step=1,
            action="Test action",
            mitre_technique_id="T1105",
            mitre_tactic_id="TA0011",
            reasoning="Matches technique.",
            confidence=0.92,
            evidence_ids=["test-evidence-id-1"],
        )
    ]

    result = mapper._valid(
        strong_mapping,
        cve(),
        [step(action="Test action")],
        {1: [candidate_t1105()]},
        {1: [{"id": "test-evidence-id-1"}]},
    )
    assert result is True

    # Low confidence mapping should fail the _valid check
    weak_mapping = [
        AttackMapping(
            step=1,
            action="Test action",
            mitre_technique_id="T1105",
            mitre_tactic_id="TA0011",
            reasoning="Might match.",
            confidence=0.60,
            evidence_ids=["test-evidence-id-1"],
        )
    ]

    result = mapper._valid(
        weak_mapping,
        cve(),
        [step(action="Test action")],
        {1: [candidate_t1105()]},
        {1: [{"id": "test-evidence-id-1"}]},
    )
    assert result is False

    # Null mapping with low confidence should pass
    null_low_confidence = [
        AttackMapping(
            step=1,
            action="Test action",
            mitre_technique_id=None,
            mitre_tactic_id=None,
            reasoning="No sufficiently supported technique.",
            confidence=0.15,
            evidence_ids=[],
        )
    ]

    result = mapper._valid(
        null_low_confidence,
        cve(),
        [step(action="Test action")],
        {1: []},
        {1: []},
    )
    assert result is True

    # Null mapping with slightly higher confidence still passes
    # (as long as it's <= 0.33 per model validator)
    null_borderline = [
        AttackMapping(
            step=1,
            action="Test action",
            mitre_technique_id=None,
            mitre_tactic_id=None,
            reasoning="Insufficient confidence.",
            confidence=0.33,
            evidence_ids=[],
        )
    ]

    result = mapper._valid(
        null_borderline,
        cve(),
        [step(action="Test action")],
        {1: []},
        {1: []},
    )
    assert result is True
