from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.enrichment.attack_mapper import evidence_id
from app.enrichment.ctid_mapper import FHGenieCTIDCVEMapper
from app.models import (
    AffectedProduct,
    AttackCandidate,
    AttackMapping,
    CVEAttackBehaviorEnvelope,
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
        '{"exploitation_techniques":['
        '{"id":"ET-1",'
        '"action":"The client downloads an attacker-controlled archive",'
        '"prerequisites":["The update endpoint is attacker-controlled"],'
        '"outcome":"The archive reaches the host","enabled_by":[],"evidence":['
        '{"source_url":"https://research.example/advisory",'
        f'"supporting_text":"{evidence_text}"}}],'
        '"reasoning":"The evidence states the delivery method."}],'
        '"primary_impacts":[],"secondary_impacts":[]}'
    )


def test_multiple_stage_items_and_causal_links_are_supported() -> None:
    evidence = {
        "source_url": "https://research.example/advisory",
        "supporting_text": "The client downloads the malicious archive.",
    }
    common = {"prerequisites": [], "outcome": "Observed outcome", "evidence": [evidence],
              "reasoning": "Directly supported."}
    envelope = CVEAttackBehaviorEnvelope.model_validate({
        "exploitation_techniques": [
            {"id": "ET-1", "action": "First method", "enabled_by": [], **common},
            {"id": "ET-2", "action": "Second method", "enabled_by": [], **common},
        ],
        "primary_impacts": [
            {"id": "PI-1", "action": "Immediate capability", "enabled_by": [], **common}
        ],
        "secondary_impacts": [
            {"id": "SI-1", "action": "Enabled behavior", "enabled_by": ["PI-1"], **common}
        ],
    })
    assert len(envelope.exploitation_techniques) == 2
    assert envelope.secondary_impacts[0].enabled_by == ["PI-1"]


@pytest.mark.asyncio
async def test_identifies_all_categories_and_preserves_explicit_nulls() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(behavior_response("The client downloads the malicious archive."))
    )

    behaviors = await FHGenieCTIDCVEMapper("test-model", api).identify_behaviors(cve(), [step()])

    assert len(behaviors.exploitation_techniques) == 1
    assert behaviors.primary_impacts == []
    assert behaviors.secondary_impacts == []
    payload = api.chat.completions.create.await_args.kwargs["messages"][1]["content"]
    assert "CWE-494" not in payload
    assert "CAPEC-187" not in payload
    assert "EVIDENCE_CATALOG" in payload
    assert api.chat.completions.create.await_args.kwargs["response_format"] == {
        "type": "json_object"
    }
    assert api.chat.completions.create.await_args.kwargs["max_completion_tokens"] == 8192
    prompt = api.chat.completions.create.await_args.kwargs["messages"][0]["content"]
    assert "Evidence entries MUST be objects, never strings" in prompt
    assert '"source_url":"https://...","supporting_text":"exact supplied text"' in prompt


@pytest.mark.asyncio
async def test_rejects_unprovenanced_evidence_without_erasing_valid_behaviors(
    tmp_path, monkeypatch
) -> None:
    import app.enrichment.ctid_mapper as ctid

    monkeypatch.setattr(ctid, "CTID_LOG_DIR", tmp_path)
    valid = behavior_response("The client downloads the malicious archive.")
    payload = __import__("json").loads(valid)
    invalid = dict(payload["exploitation_techniques"][0])
    invalid["id"] = "ET-2"
    invalid["evidence"] = ["The client downloads the malicious archive."]
    payload["exploitation_techniques"].append(invalid)
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(__import__("json").dumps(payload))
    )

    behaviors = await FHGenieCTIDCVEMapper("test-model", api).identify_behaviors(cve(), [step()])

    assert [item.id for item in behaviors.exploitation_techniques] == ["ET-1"]
    diagnostics = [__import__("json").loads(path.read_text()) for path in tmp_path.glob("*.json")]
    assert all(item["status"] == "partial_validation_failure" for item in diagnostics)
    assert "Input should be a valid dictionary" in diagnostics[0]["validation_errors"][0]["error"]
    assert all(item["legitimate_empty_result"] is False for item in diagnostics)
    assert api.chat.completions.create.await_count == 2


@pytest.mark.asyncio
async def test_invalid_behavior_envelope_is_logged_and_not_treated_as_empty(
    tmp_path, monkeypatch
) -> None:
    import app.enrichment.ctid_mapper as ctid

    monkeypatch.setattr(ctid, "CTID_LOG_DIR", tmp_path)
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response('{"exploitation_techniques":'))

    with pytest.raises(ctid.CTIDMappingError, match="invalid CTID behavior JSON"):
        await FHGenieCTIDCVEMapper("test-model", api).identify_behaviors(cve(), [step()])

    diagnostics = list(tmp_path.glob("*.json"))
    assert len(diagnostics) == 2
    logged = __import__("json").loads(diagnostics[0].read_text())
    assert logged["status"] == "validation_failed"
    assert logged["legitimate_empty_result"] is False
    assert "invalid CTID behavior JSON" in logged["validation_errors"][0]["error"]


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

    assert mappings.exploitation_techniques[0].mitre_technique_id == "T1105"
    assert mappings.primary_impacts == []
    graph.attack_candidates.assert_awaited_once()
    mapper.map_steps.assert_awaited_once()
    validator.validate.assert_awaited_once()
