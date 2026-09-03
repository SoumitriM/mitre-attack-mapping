from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.config import Settings
from app.enrichment.attack_mapper import evidence_id
from app.enrichment.validation_agent import (
    FHGenieValidationAgent,
    ValidationResponseError,
    _parse_validation_response,
)
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
        cvss=CVSSMetrics(
            version="3.1", attack_vector="NETWORK", user_interaction="REQUIRED"
        ),
        cwe_ids=["CWE-494"],
        capec_ids=["CAPEC-187"],
    )


def step(number: int = 1, action: str = "Download malicious archive") -> ExploitStep:
    return ExploitStep.model_validate(
        {
            "step": number,
            "action": action,
            "prerequisites": ["Victim checks for an update"],
            "outcome": "Archive reaches the Windows host",
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "The client downloads the malicious archive.",
                }
            ],
        }
    )


def mapping(item: ExploitStep, confidence: float = 0.91) -> AttackMapping:
    ev_id = evidence_id(
        str(item.evidence[0].source_url), item.evidence[0].supporting_text
    )
    return AttackMapping(
        step=item.step,
        action=item.action,
        mitre_technique_id="T1105",
        mitre_tactic_id="TA0011",
        reasoning="The archive is transferred to the target.",
        confidence=confidence,
        evidence_ids=[ev_id],
    )


def candidate(platforms: list[str] | None = None) -> AttackCandidate:
    return AttackCandidate(
        mitre_technique_id="T1105",
        name="Ingress Tool Transfer",
        description="Adversaries may transfer files from an external system.",
        platforms=platforms or ["Windows"],
        tactics={"command-and-control": "TA0011"},
    )


def settings() -> Settings:
    return Settings(_env_file=None, fh_genie_model="test-model")


def test_validation_schema_rejects_more_than_one_step() -> None:
    item = step()
    proposed = mapping(item)
    validated = (
        '{"step":1,"action":"Download malicious archive",'
        '"proposed_technique_id":"T1105","mitre_tactic_id":"TA0011",'
        f'"evidence_ids":["{proposed.evidence_ids[0]}"],'
        '"validation":{"status":"validated",'
        '"checks":{"technique_exists":true,"tactic_valid":true,'
        '"platform_compatible":true,"evidence_support":true,"semantic_match":true},'
        '"reasoning":"Grounded transfer.","validator_confidence":0.9}}'
    )

    with pytest.raises(ValidationResponseError) as raised:
        _parse_validation_response(f'{{"steps":[{validated},{validated}]}}')

    assert raised.value.failure_reason == "schema_validation_failed"


@pytest.mark.asyncio
async def test_validates_grounded_official_mapping() -> None:
    item = step()
    proposed = mapping(item)
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"steps":[{"step":1,"action":"Download malicious archive",'
            '"proposed_technique_id":"T1105","mitre_tactic_id":"TA0011",'
            f'"evidence_ids":["{proposed.evidence_ids[0]}"],'
            '"validation":{"status":"validated",'
            '"checks":{"technique_exists":true,"tactic_valid":true,'
            '"platform_compatible":true,"evidence_support":true,"semantic_match":true},'
            '"reasoning":"The cited transfer behavior matches the official technique.",'
            '"validator_confidence":0.9}}]}'
        )
    )

    chain = await FHGenieValidationAgent(settings(), api).validate(
        cve(), [item], [proposed], {"T1105": candidate()}
    )

    assert chain[0].validation.status == "validated"
    assert chain[0].validation.validator_confidence == 0.9


@pytest.mark.asyncio
@pytest.mark.parametrize("official", [{}, {"T1105": candidate(["Linux"])}])
async def test_official_or_platform_failure_forces_null_mapping(
    official: dict[str, AttackCandidate],
) -> None:
    item = step()
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"steps":[{"step":1,"action":"Download malicious archive",'
            '"proposed_technique_id":null,"mitre_tactic_id":null,'
            '"evidence_ids":[],'
            '"validation":{"status":"unmapped",'
            '"checks":{"technique_exists":false,"tactic_valid":false,'
            '"platform_compatible":false,"evidence_support":false,"semantic_match":false},'
            '"reasoning":"The official validation gate rejected the mapping.",'
            '"validator_confidence":0.1}}]}'
        )
    )

    chain = await FHGenieValidationAgent(settings(), api).validate(
        cve(), [item], [mapping(item)], official
    )

    assert chain[0].proposed_technique_id is None


@pytest.mark.asyncio
async def test_rejects_changed_mapping_or_increased_confidence() -> None:
    item = step()
    proposed = mapping(item)
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"steps":[{"step":1,"action":"Download malicious archive",'
            '"proposed_technique_id":"T9999","mitre_tactic_id":"TA0011",'
            f'"evidence_ids":["{proposed.evidence_ids[0]}"],'
            '"validation":{"status":"validated",'
            '"checks":{"technique_exists":true,"tactic_valid":true,'
            '"platform_compatible":true,"evidence_support":true,"semantic_match":true},'
            '"reasoning":"Invented mapping.",'
            '"validator_confidence":0.99}}]}'
        )
    )

    chain = await FHGenieValidationAgent(settings(), api).validate(
        cve(), [item], [proposed], {"T1105": candidate()}
    )

    assert chain[0].validation.status == "unmapped"
    assert "changed or retained" in chain[0].validation.reasoning


def test_empty_cve_platforms_are_unknown_and_do_not_force_rejection() -> None:
    empty_platform_cve = cve().model_copy(deep=True)
    empty_platform_cve.affected_products[0].platforms = []
    agent = FHGenieValidationAgent(settings(), MagicMock())

    prepared = agent._prepare(
        empty_platform_cve,
        [step()],
        [mapping(step())],
        {"T1105": candidate(["Windows"])},
        {},
    )

    assert prepared[0]["platform_check_result"] == "unknown"
    assert prepared[0]["forced_rejection"] is None


@pytest.mark.asyncio
async def test_one_semantic_validation_failure_does_not_affect_next_step() -> None:
    first = step(action="Download first archive")
    second = step(2, action="Download second archive")
    api = MagicMock()
    api.chat.completions.create = AsyncMock(side_effect=[
        response("not json"),
        response("still not json"),
        response(
            '{"status":"validated",'
            '"checks":{"technique_exists":true,"tactic_valid":true,'
            '"platform_compatible":true,"evidence_support":true,"semantic_match":true},'
            '"reasoning":"The second mapping is supported.",'
            '"validator_confidence":0.8}'
        ),
    ])

    chain = await FHGenieValidationAgent(settings(), api).validate(
        cve(),
        [first, second],
        [mapping(first), mapping(second)],
        {"T1105": candidate()},
    )

    assert chain[0].validation.status == "unmapped"
    assert "Invalid FH Genie validation JSON" in chain[0].validation.reasoning
    assert chain[1].validation.status == "validated"


@pytest.mark.asyncio
async def test_identical_duplicate_is_forced_unmapped_but_all_steps_remain() -> None:
    first = step()
    second = step(2)
    first_mapping = mapping(first)
    second_mapping = mapping(second)
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"steps":['
            '{"step":1,"action":"Download malicious archive",'
            '"proposed_technique_id":"T1105","mitre_tactic_id":"TA0011",'
            f'"evidence_ids":["{first_mapping.evidence_ids[0]}"],'
            '"validation":{"status":"validated",'
            '"checks":{"technique_exists":true,"tactic_valid":true,'
            '"platform_compatible":true,"evidence_support":true,"semantic_match":true},'
            '"reasoning":"Grounded transfer.","validator_confidence":0.9}}]}'
        )
    )

    chain = await FHGenieValidationAgent(settings(), api).validate(
        cve(),
        [first, second],
        [first_mapping, second_mapping],
        {"T1105": candidate()},
    )

    assert len(chain) == 2
    assert chain[1].proposed_technique_id is None
