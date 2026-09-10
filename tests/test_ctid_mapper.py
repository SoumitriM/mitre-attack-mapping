from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.enrichment.attack_mapper import evidence_id
from app.enrichment.ctid_mapper import CTIDMappingError, FHGenieCTIDCVEMapper
from app.models import (
    AffectedProduct,
    AttackCandidate,
    AttackMapping,
    CVERecord,
    ExploitStep,
    ValidatedAttackStep,
    ValidationChecks,
    ValidationDetails,
    ValidationStatus,
)


def response(content: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def cve() -> CVERecord:
    return CVERecord(
        cve_id="CVE-2026-22306",
        description="A client retrieves an attacker-controlled update.",
        affected_products=[AffectedProduct(product="OZOLS", platforms=["Windows"])],
        cwe_ids=["CWE-494"],
        capec_ids=["CAPEC-187"],
    )


def step() -> ExploitStep:
    return ExploitStep.model_validate(
        {
            "step": 1,
            "action": "The client downloads a malicious archive",
            "prerequisites": ["The update endpoint is attacker-controlled"],
            "outcome": "The archive reaches the host",
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "The client downloads the malicious archive.",
                }
            ],
        }
    )


def behavior_response(evidence_text: str) -> str:
    return (
        '{"behaviors":['
        '{"category":"exploitation_technique",'
        '"action":"The client downloads an attacker-controlled archive",'
        '"prerequisites":["The update endpoint is attacker-controlled"],'
        '"outcome":"The archive reaches the host","evidence":['
        '{"source_url":"https://research.example/advisory",'
        f'"supporting_text":"{evidence_text}"}}],'
        '"reasoning":"The evidence states the delivery method."},'
        '{"category":"primary_impact","action":null,"prerequisites":[],'
        '"outcome":null,"evidence":[],"reasoning":"No initial benefit is stated."},'
        '{"category":"secondary_impact","action":null,"prerequisites":[],'
        '"outcome":null,"evidence":[],"reasoning":"No enabled later behavior is stated."}]}'
    )


@pytest.mark.asyncio
async def test_identifies_all_categories_and_preserves_explicit_nulls() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(behavior_response("The client downloads the malicious archive."))
    )

    behaviors = await FHGenieCTIDCVEMapper("test-model", api).identify_behaviors(cve(), [step()])

    assert [item.category.value for item in behaviors] == [
        "exploitation_technique",
        "primary_impact",
        "secondary_impact",
    ]
    assert behaviors[0].action is not None
    assert behaviors[1].action is None
    payload = api.chat.completions.create.await_args.kwargs["messages"][1]["content"]
    assert "CWE-494" not in payload
    assert "CAPEC-187" not in payload


@pytest.mark.asyncio
async def test_rejects_evidence_not_attached_to_existing_steps() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(behavior_response("Evidence invented by the model."))
    )

    with pytest.raises(CTIDMappingError, match="evidence"):
        await FHGenieCTIDCVEMapper("test-model", api).identify_behaviors(cve(), [step()])

    assert api.chat.completions.create.await_count == 2


@pytest.mark.asyncio
async def test_maps_supported_categories_through_existing_retrieval_and_validator() -> None:
    item = step()
    ev_id = evidence_id(str(item.evidence[0].source_url), item.evidence[0].supporting_text)
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(behavior_response(item.evidence[0].supporting_text))
    )
    graph = MagicMock()
    graph.attack_candidates = AsyncMock(
        return_value=[
            AttackCandidate(
                mitre_technique_id="T1105",
                name="Ingress Tool Transfer",
                description="Transfer files from an external system.",
                platforms=["Windows"],
                tactics={"command-and-control": "TA0011"},
            )
        ]
    )
    graph.official_attack_context = AsyncMock(return_value={})
    mapper = MagicMock()
    mapper.map_steps = AsyncMock(
        return_value=[
            AttackMapping(
                step=1,
                action="The client downloads an attacker-controlled archive",
                mitre_technique_id="T1105",
                mitre_tactic_id="TA0011",
                reasoning="The behavior transfers a file.",
                confidence=0.8,
                evidence_ids=[ev_id],
            )
        ]
    )
    validator = MagicMock()
    validator.validate = AsyncMock(
        return_value=[
            ValidatedAttackStep(
                step=1,
                action="The client downloads an attacker-controlled archive",
                proposed_technique_id="T1105",
                mitre_tactic_id="TA0011",
                evidence_ids=[ev_id],
                validation=ValidationDetails(
                    status=ValidationStatus.VALIDATED,
                    checks=ValidationChecks(
                        technique_exists=True,
                        tactic_valid=True,
                        platform_compatible=True,
                        evidence_support=True,
                        semantic_match=True,
                    ),
                    reasoning="The evidence supports the official technique.",
                    validator_confidence=0.8,
                ),
            )
        ]
    )

    mappings = await FHGenieCTIDCVEMapper("test-model", api).map(
        cve(), [item], graph, mapper, validator
    )

    assert len(mappings) == 3
    assert mappings[0].mitre_technique_id == "T1105"
    assert mappings[1].mitre_technique_id is None
    graph.attack_candidates.assert_awaited_once()
    mapper.map_steps.assert_awaited_once()
    validator.validate.assert_awaited_once()
