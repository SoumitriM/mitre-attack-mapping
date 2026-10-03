from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.enrichment.attack_mapper import evidence_id
from app.enrichment.ctid_mapper import (
    CTIDNormalizedSemantics,
    FHGenieCTIDCVEMapper,
)
from app.models import (
    AffectedProduct,
    AttackCandidate,
    AttackMapping,
    CVEAttackBehavior,
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


def normalized() -> CTIDNormalizedSemantics:
    return CTIDNormalizedSemantics(
        exploitation_behaviors=["Retrieve an attacker-controlled update"],
        primary_capabilities=["Gain execution of attacker-controlled code"],
        secondary_behaviors=["Transfer an additional attacker-controlled tool"],
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


@pytest.mark.asyncio
async def test_description_normalization_uses_one_call_and_atomic_schema() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"exploitation_behaviors":["Retrieve an attacker-controlled update"],'
            '"primary_capabilities":["Gain execution of attacker-controlled code"],'
            '"secondary_behaviors":[]}'
        )
    )

    result = await FHGenieCTIDCVEMapper("test-model", api).normalize_description(cve())

    api.chat.completions.create.assert_awaited_once()
    assert result.exploitation_behaviors == ["Retrieve an attacker-controlled update"]
    assert result.primary_capabilities == ["Gain execution of attacker-controlled code"]
    assert result.secondary_behaviors == []


@pytest.mark.asyncio
async def test_description_ctid_mapping_uses_one_closed_set_call() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"exploitation_techniques":[{"technique_id":"T1190",'
            '"reasoning":"The description directly states exploitation."}],'
            '"primary_impacts":[],"secondary_impacts":[]}'
        )
    )
    candidate = AttackCandidate(
        mitre_technique_id="T1190",
        name="Exploit Public-Facing Application",
        description="Exploit a weakness in an Internet-facing system.",
        tactics={"initial-access": "TA0001"},
        retrieved_by=["exploitation_behaviors[0]"],
    )

    mappings = await FHGenieCTIDCVEMapper("test-model", api).map_description(
        cve(),
        normalized(),
        {"exploitation": [candidate], "primary_impact": [], "secondary_impact": []},
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-22306",
    )

    api.chat.completions.create.assert_awaited_once()
    assert mappings.exploitation_techniques[0].mitre_technique_id == "T1190"
    assert mappings.primary_impacts == []
    request = api.chat.completions.create.await_args.kwargs
    assert request["response_format"] == {"type": "json_object"}
    payload = request["messages"][1]["content"]
    assert "exploitation_candidates" in payload
    assert "primary_impact_candidates" in payload
    assert "secondary_impact_candidates" in payload
    assert '"normalized"' in payload
    assert "exploitation_behaviors[0]" in payload
    assert "T1190" in payload


@pytest.mark.asyncio
async def test_description_ctid_mapping_accepts_schema_valid_unretrieved_ids() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"exploitation_techniques":[{"technique_id":"T9999",'
            '"reasoning":"Unsupported."}],"primary_impacts":[],"secondary_impacts":[]}'
        )
    )

    mappings = await FHGenieCTIDCVEMapper("test-model", api).map_description(
        cve(),
        normalized(),
        {"exploitation": [], "primary_impact": [], "secondary_impact": []},
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-22306",
    )
    assert mappings.exploitation_techniques[0].mitre_technique_id == "T9999"
    assert mappings.exploitation_techniques[0].mitre_tactic_id is None
    assert mappings.exploitation_techniques[0].validation is None



@pytest.mark.asyncio
async def test_description_ctid_mapping_preserves_role_specific_causal_links() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"exploitation_techniques":[{"technique_id":"T1190",'
            '"reasoning":"Direct exploit.","enabled_by":[]}],'
            '"primary_impacts":[{"technique_id":"T1059",'
            '"reasoning":"Immediate execution.","enabled_by":["ET-1"]}],'
            '"secondary_impacts":[{"technique_id":"T1105",'
            '"reasoning":"Enabled transfer.","enabled_by":["PI-1"]}]}'
        )
    )
    et = AttackCandidate(
        mitre_technique_id="T1190",
        name="Exploit Public-Facing Application",
        description="Exploit a public-facing application.",
        tactics={"initial-access": "TA0001"},
    )
    pi = AttackCandidate(
        mitre_technique_id="T1059",
        name="Command and Scripting Interpreter",
        description="Execute commands.",
        tactics={"execution": "TA0002"},
    )
    si = AttackCandidate(
        mitre_technique_id="T1105",
        name="Ingress Tool Transfer",
        description="Transfer tools.",
        tactics={"command-and-control": "TA0011"},
    )

    mappings = await FHGenieCTIDCVEMapper("test-model", api).map_description(
        cve(),
        normalized(),
        {"exploitation": [et], "primary_impact": [pi], "secondary_impact": [si]},
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-22306",
    )

    assert mappings.primary_impacts[0].enabled_by == ["ET-1"]
    assert mappings.secondary_impacts[0].enabled_by == ["PI-1"]


def causal_behavior_payload(
    *,
    et_enabled_by: list[str] | None = None,
    pi_enabled_by: list[str] | None = None,
    si_enabled_by: list[str] | None = None,
) -> str:
    import json

    evidence = [
        {
            "source_url": "https://research.example/advisory",
            "supporting_text": "The client downloads the malicious archive.",
        }
    ]
    common = {"prerequisites": [], "evidence": evidence, "reasoning": "Direct evidence."}
    return json.dumps(
        {
            "exploitation_techniques": [
                {
                    "id": "ET-1",
                    "action": "Trigger a stack-based buffer overflow",
                    "outcome": "The vulnerable return address is overwritten",
                    "enabled_by": et_enabled_by or [],
                    **common,
                }
            ],
            "primary_impacts": [
                {
                    "id": "PI-1",
                    "action": "Obtain remote code execution",
                    "outcome": "Code execution is available",
                    "enabled_by": ["ET-1"] if pi_enabled_by is None else pi_enabled_by,
                    **common,
                }
            ],
            "secondary_impacts": [
                {
                    "id": "SI-1",
                    "action": "Clear forensic logs",
                    "outcome": "Evidence is impaired",
                    "enabled_by": ["PI-1"] if si_enabled_by is None else si_enabled_by,
                    **common,
                }
            ],
        }
    )


def test_valid_et_pi_si_chain_is_preserved() -> None:
    result = FHGenieCTIDCVEMapper._parse_behaviors(causal_behavior_payload(), [step()])

    assert result.errors == []
    assert result.relationship_warnings == []
    assert result.envelope.primary_impacts[0].enabled_by == ["ET-1"]
    assert result.envelope.secondary_impacts[0].enabled_by == ["PI-1"]


@pytest.mark.parametrize(
    ("kwargs", "stage", "expected_links"),
    [
        ({"et_enabled_by": ["PI-1"]}, "exploitation_techniques", ["PI-1"]),
        ({"pi_enabled_by": ["ET-404"]}, "primary_impacts", ["ET-404"]),
        ({"si_enabled_by": ["PI-404"]}, "secondary_impacts", ["PI-404"]),
    ],
)
def test_schema_valid_causal_edge_is_preserved(
    kwargs: dict[str, list[str]], stage: str, expected_links: list[str]
) -> None:
    result = FHGenieCTIDCVEMapper._parse_behaviors(causal_behavior_payload(**kwargs), [step()])

    assert result.errors == []
    assert len(getattr(result.envelope, stage)) == 1
    assert getattr(result.envelope, stage)[0].enabled_by == expected_links
    assert result.relationship_warnings == []


@pytest.mark.asyncio
async def test_schema_valid_relationship_does_not_trigger_retry(tmp_path, monkeypatch) -> None:
    import app.enrichment.ctid_mapper as ctid

    monkeypatch.setattr(ctid, "CTID_LOG_DIR", tmp_path)
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(causal_behavior_payload(pi_enabled_by=["ET-404"]))
    )

    envelope = await FHGenieCTIDCVEMapper("test-model", api).identify_behaviors(cve(), [step()])

    assert envelope.primary_impacts[0].enabled_by == ["ET-404"]
    api.chat.completions.create.assert_awaited_once()


def test_multiple_stage_items_and_causal_links_are_supported() -> None:
    evidence = {
        "source_url": "https://research.example/advisory",
        "supporting_text": "The client downloads the malicious archive.",
    }
    common = {
        "prerequisites": [],
        "outcome": "Observed outcome",
        "evidence": [evidence],
        "reasoning": "Directly supported.",
    }
    envelope = CVEAttackBehaviorEnvelope.model_validate(
        {
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
        }
    )
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
    decoded_payload = __import__("json").loads(payload)
    assert "evidence" not in decoded_payload["exploit_steps"][0]
    assert decoded_payload["exploit_steps"][0]["evidence_ids"]
    assert api.chat.completions.create.await_args.kwargs["response_format"] == {
        "type": "json_object"
    }
    assert api.chat.completions.create.await_args.kwargs["max_completion_tokens"] == 4096
    prompt = api.chat.completions.create.await_args.kwargs["messages"][0]["content"]
    assert "Evidence entries MUST be objects, never strings" in prompt
    assert "merge them into a single exploitation technique" in prompt
    assert "unless they independently exploit distinct vulnerabilities" in prompt
    assert "try to map exploitation techniques, primary impacts, and" in prompt
    assert "Any item may remain unmapped" in prompt
    assert '"source_url": "https://..."' in prompt
    assert '"supporting_text": "exact supplied text"' in prompt


def test_parser_accepts_json_markdown_fence_without_retry() -> None:
    fenced = f"```json\n{behavior_response('The client downloads the malicious archive.')}\n```"

    result = FHGenieCTIDCVEMapper._parse_behaviors(fenced, [step()])

    assert [item.id for item in result.envelope.exploitation_techniques] == ["ET-1"]
    assert result.errors == []


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
async def test_maps_categories_without_independent_validation() -> None:
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
    validator.validate.assert_not_awaited()
    graph.official_attack_context.assert_not_awaited()
    assert mapper.map_steps.await_args.kwargs == {"schema_only": True}
    assert mappings.exploitation_techniques[0].validation is None


@pytest.mark.asyncio
async def test_et_pi_and_si_are_sent_through_attack_mapping() -> None:
    evidence = step().evidence
    envelope = CVEAttackBehaviorEnvelope(
        exploitation_techniques=[
            CVEAttackBehavior(
                id="ET-1",
                action="Trigger a stack-based buffer overflow",
                outcome="Overflow",
                evidence=evidence,
                reasoning="Supported.",
            )
        ],
        primary_impacts=[
            CVEAttackBehavior(
                id="PI-1",
                action="Obtain remote code execution",
                outcome="RCE",
                enabled_by=["ET-1"],
                evidence=evidence,
                reasoning="Supported.",
            )
        ],
        secondary_impacts=[
            CVEAttackBehavior(
                id="SI-1",
                action="Clear forensic logs",
                outcome="Logs cleared",
                enabled_by=["PI-1"],
                evidence=evidence,
                reasoning="Supported.",
            )
        ],
    )
    graph = MagicMock()
    graph.attack_candidates = AsyncMock(return_value=[])
    graph.official_attack_context = AsyncMock(return_value={})
    attack_mapper = MagicMock()
    attack_mapper.map_steps = AsyncMock(return_value=[])
    validator = MagicMock()
    validator.validate = AsyncMock(return_value=[])
    ctid_mapper = FHGenieCTIDCVEMapper("test-model", MagicMock())
    ctid_mapper.identify_behaviors = AsyncMock(return_value=envelope)

    mappings = await ctid_mapper.map(cve(), [step()], graph, attack_mapper, validator)

    retrieved_actions = [call.args[0].action for call in graph.attack_candidates.await_args_list]
    mapped_actions = [call.args[1][0].action for call in attack_mapper.map_steps.await_args_list]
    assert retrieved_actions == [
        "Trigger a stack-based buffer overflow",
        "Obtain remote code execution",
        "Clear forensic logs",
    ]
    assert mapped_actions == retrieved_actions
    assert mappings.primary_impacts[0].mitre_technique_id is None
    assert mappings.primary_impacts[0].enabled_by == ["ET-1"]
    assert mappings.primary_impacts[0].confidence == 0.0


def test_cve_2025_0282_regression_shape_excludes_reconnaissance() -> None:
    result = FHGenieCTIDCVEMapper._parse_behaviors(causal_behavior_payload(), [step()])
    actions = {
        stage: [item.action.lower() for item in getattr(result.envelope, stage)]
        for stage in ("exploitation_techniques", "primary_impacts", "secondary_impacts")
    }

    assert any(
        "stack-based buffer overflow" in action for action in actions["exploitation_techniques"]
    )
    assert any("remote code execution" in action for action in actions["primary_impacts"])
    assert actions["secondary_impacts"]
    assert all("version" not in action for action in actions["exploitation_techniques"])
    assert (
        "version detection"
        in __import__(
            "app.enrichment.ctid_mapper", fromlist=["CTID_SYSTEM_PROMPT"]
        ).CTID_SYSTEM_PROMPT
    )


def test_schema_valid_unprovenanced_evidence_and_duplicate_ids_are_preserved() -> None:
    import json

    payload = json.loads(causal_behavior_payload())
    behavior = payload["exploitation_techniques"][0]
    behavior["evidence"][0]["supporting_text"] = "Text absent from the supplied evidence."
    payload["exploitation_techniques"].append(behavior.copy())
    result = FHGenieCTIDCVEMapper._parse_behaviors(json.dumps(payload), [step()])
    assert result.errors == []
    assert len(result.envelope.exploitation_techniques) == 2
    assert result.envelope.exploitation_techniques[0].evidence[0].supporting_text == (
        "Text absent from the supplied evidence."
    )
