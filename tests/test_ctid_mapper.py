import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.analysis import CVEAnalysisService, attack_chain_from_mappings
from app.config import Settings
from app.enrichment.ctid_mapper import CTIDMappingError, FHGenieCTIDCVEMapper
from app.models import AttackMapping, CVELevelAttackMappings, CVERecord, ExploitStep


@pytest.fixture(autouse=True)
def isolate_ctid_logs(tmp_path, monkeypatch):
    monkeypatch.setattr("app.enrichment.ctid_mapper.CTID_LOG_DIR", tmp_path)


def sources():
    actions = [
        "Send a crafted request to exploit the server",
        "Execute commands through the compromised service",
        "Clear the service logs using the gained execution capability",
    ]
    steps = [ExploitStep.model_validate({
        "step": index,
        "action": action,
        "outcome": "Command execution obtained" if index == 1 else "Observed consequence",
        "evidence": [{
            "source_url": "https://research.example/advisory",
            "supporting_text": "A crafted request permits command execution and log removal.",
        }],
    }) for index, action in enumerate(actions, start=1)]
    mappings = [AttackMapping(
        step=index, action=action,
        mitre_technique_id=technique, mitre_tactic_id=tactic,
        reasoning="Existing attack mapping.", confidence=0.8,
        evidence_ids=[f"existing-evidence-{index}"],
    ) for index, (action, technique, tactic) in enumerate(zip(
        actions, ["T1190", "T1059", "T1070"], ["TA0001", "TA0002", "TA0005"], strict=True
    ), start=1)]
    return steps, mappings, attack_chain_from_mappings(steps, mappings)


def node(prefix, index, action, enabled_by, source_step=None, supporting_steps=None):
    return {
        "id": f"{prefix}-{index}", "action": action, "enabled_by": enabled_by,
        "source_step": source_step, "supporting_steps": supporting_steps or [1],
        "reasoning": "Evidence establishes this causal relationship.",
    }


def payload(steps, *, outcome_pi=False):
    return {
        "exploitation_techniques": [node("ET", 1, steps[0].action, [], 1, [1])],
        "primary_impacts": [node(
            "PI", 1, "Command execution obtained" if outcome_pi else steps[1].action, ["ET-1"],
            None if outcome_pi else 2, [1] if outcome_pi else [2]
        )],
        "secondary_impacts": [node("SI", 1, steps[2].action, ["PI-1"], 3, [3])],
    }


def mapper_for(data):
    api = MagicMock()
    content = data if isinstance(data, str) else json.dumps(data)
    api.chat.completions.create = AsyncMock(return_value=SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    ))
    return FHGenieCTIDCVEMapper("test-model", api), api


@pytest.mark.asyncio
async def test_reuses_source_ids_with_one_causal_call_and_no_input_mutation():
    steps, mappings, chain = sources()
    before = [[item.model_dump(mode="json") for item in group]
              for group in (steps, mappings, chain)]
    ctid, api = mapper_for(payload(steps))
    result = await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)
    api.chat.completions.create.assert_awaited_once()
    nodes = [result.exploitation_techniques[0], result.primary_impacts[0],
             result.secondary_impacts[0]]
    for actual, expected in zip(nodes, mappings, strict=True):
        assert actual.mitre_technique_id == expected.mitre_technique_id
        assert actual.mitre_tactic_id == expected.mitre_tactic_id
        assert actual.confidence == expected.confidence
        assert actual.evidence_ids == expected.evidence_ids
        assert actual.validation is None
    assert nodes[1].enabled_by == ["ET-1"]
    assert nodes[2].enabled_by == ["PI-1"]
    assert before == [[item.model_dump(mode="json") for item in group]
                      for group in (steps, mappings, chain)]
    assert CVELevelAttackMappings.model_validate_json(result.model_dump_json()) == result
    request = api.chat.completions.create.await_args.kwargs
    supplied = json.loads(request["messages"][1]["content"])
    assert supplied["attack_chain"] == before[2]
    assert supplied["attack_mappings"] == before[1]
    assert "candidates" not in supplied
    assert "not ATT&CK mapping" in request["messages"][0]["content"]


@pytest.mark.asyncio
async def test_outcome_pi_and_si_never_borrow_an_exploit_mapping():
    steps, mappings, chain = sources()
    data = payload(steps, outcome_pi=True)
    data["secondary_impacts"] = [node("SI", 1, "Audit evidence lost", ["PI-1"])]
    ctid, _ = mapper_for(data)
    result = await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)
    assert result.exploitation_techniques[0].mitre_technique_id == "T1190"
    for item in [result.primary_impacts[0], result.secondary_impacts[0]]:
        assert item.mitre_technique_id is None
        assert item.mitre_tactic_id is None
        assert item.confidence == 0.0
        assert item.evidence_ids
    assert result.secondary_impacts[0].enabled_by == ["PI-1"]


@pytest.mark.asyncio
async def test_unmapped_source_behavior_remains_unmapped_in_every_role():
    steps, _, _ = sources()
    mappings = [AttackMapping(step=item.step, action=item.action,
                              reasoning="No existing mapping.", confidence=0.2) for item in steps]
    chain = attack_chain_from_mappings(steps, mappings)
    ctid, _ = mapper_for(payload(steps))
    result = await ctid.map(CVERecord(cve_id="CVE-2026-57112"), steps, chain, mappings)
    assert len(result.exploitation_techniques) == 1
    assert len(result.primary_impacts) == 1
    assert len(result.secondary_impacts) == 1
    for item in [*result.exploitation_techniques, *result.primary_impacts,
                 *result.secondary_impacts]:
        assert item.mitre_technique_id is None
        assert item.mitre_tactic_id is None


@pytest.mark.asyncio
async def test_final_chain_nulls_are_not_replaced_by_raw_proposals():
    steps, proposals, _ = sources()
    chain = attack_chain_from_mappings(steps, [])
    ctid, _ = mapper_for(payload(steps))
    result = await ctid.map(CVERecord(cve_id="CVE-2026-57112"), steps, chain, proposals)
    for item in [*result.exploitation_techniques, *result.primary_impacts,
                 *result.secondary_impacts]:
        assert item.mitre_technique_id is None
        assert item.mitre_tactic_id is None


@pytest.mark.asyncio
async def test_copies_source_ids_without_semantic_attack_validation():
    steps, mappings, _ = sources()
    mappings[0] = mappings[0].model_copy(update={
        "mitre_technique_id": "T9999", "mitre_tactic_id": "TA9999",
    })
    chain = attack_chain_from_mappings(steps, mappings)
    ctid, _ = mapper_for(payload(steps))
    result = await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)
    assert result.exploitation_techniques[0].mitre_technique_id == "T9999"
    assert result.exploitation_techniques[0].mitre_tactic_id == "TA9999"
    assert result.exploitation_techniques[0].validation is None


@pytest.mark.asyncio
async def test_multiple_paths_preserve_separate_et_pi_si_links():
    steps, mappings, chain = sources()
    steps[1] = steps[1].model_copy(update={"action": "Exploit a separate endpoint"})
    chain = attack_chain_from_mappings(steps, mappings)
    data = {
        "exploitation_techniques": [
            node("ET", 1, steps[0].action, [], 1, [1]),
            node("ET", 2, steps[1].action, [], 2, [2]),
        ],
        "primary_impacts": [
            node("PI", 1, "First capability obtained", ["ET-1"]),
            node("PI", 2, "Separate capability obtained", ["ET-2"]),
        ],
        "secondary_impacts": [node("SI", 1, steps[2].action, ["PI-2"], 3, [3])],
    }
    ctid, _ = mapper_for(data)
    result = await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)
    assert len(result.exploitation_techniques) == 2
    assert result.primary_impacts[0].enabled_by == ["ET-1"]
    assert result.primary_impacts[1].enabled_by == ["ET-2"]
    assert result.secondary_impacts[0].enabled_by == ["PI-2"]


@pytest.mark.parametrize("invalid", [
    "missing-field", "duplicate-id", "wrong-role-id", "unknown-predecessor", "et-to-si",
    "et-predecessor", "missing-pi-predecessor", "new-technique", "wrong-type",
])
@pytest.mark.asyncio
async def test_rejects_only_structurally_invalid_ctid_responses(invalid):
    steps, mappings, chain = sources()
    data = payload(steps)
    et, pi, si = (data[field][0] for field in (
        "exploitation_techniques", "primary_impacts", "secondary_impacts"
    ))
    if invalid == "missing-field":
        del et["enabled_by"]
    elif invalid == "duplicate-id":
        data["exploitation_techniques"].append(et.copy())
    elif invalid == "wrong-role-id":
        pi["id"] = "ET-2"
    elif invalid == "unknown-predecessor":
        pi["enabled_by"] = ["ET-404"]
    elif invalid == "et-to-si":
        si["enabled_by"] = ["ET-1"]
    elif invalid == "et-predecessor":
        et["enabled_by"] = ["PI-1"]
    elif invalid == "missing-pi-predecessor":
        pi["enabled_by"] = []
    elif invalid == "new-technique":
        pi["technique_id"] = "T9999"
    elif invalid == "wrong-type":
        et["enabled_by"] = [1]
    ctid, api = mapper_for(data)
    with pytest.raises(CTIDMappingError, match="invalid CTID causal structure"):
        await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)
    api.chat.completions.create.assert_awaited_once()


@pytest.mark.parametrize("content", ["", "{", '[]', '{"exploitation_techniques":{}}'])
@pytest.mark.asyncio
async def test_invalid_json_or_envelope_is_explicit_failure(content, tmp_path):
    steps, mappings, chain = sources()
    ctid, _ = mapper_for(content)
    with pytest.raises(CTIDMappingError):
        await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)
    diagnostic = json.loads(next(tmp_path.glob("*ctid_behavior*.json")).read_text())
    assert diagnostic["status"] == "validation_failed"
    assert diagnostic["validation_error"]


@pytest.mark.asyncio
async def test_empty_structure_is_valid_and_markdown_json_is_accepted():
    steps, mappings, chain = sources()
    data = {"exploitation_techniques": [], "primary_impacts": [], "secondary_impacts": []}
    ctid, _ = mapper_for(f"```json\n{json.dumps(data)}\n```")
    assert await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings) == (
        CVELevelAttackMappings()
    )


@pytest.mark.asyncio
async def test_no_chain_skips_ctid_llm():
    ctid, api = mapper_for({})
    assert await ctid.map(CVERecord(cve_id="CVE-2026-33557"), [], [], []) == (
        CVELevelAttackMappings()
    )
    api.chat.completions.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_ctid_enabled_and_disabled_preserve_identical_attack_outputs(monkeypatch):
    steps, mappings, chain = sources()
    cve = CVERecord(cve_id="CVE-2026-33557", description="Existing evidence.")
    monkeypatch.setattr("app.analysis.CVEIngestionService.analyze", AsyncMock(return_value=cve))
    graph = MagicMock()
    graph.verify_taxonomy = AsyncMock()
    graph.attack_candidates = AsyncMock(return_value=[])
    graph.description_attack_candidates = AsyncMock()
    agent = MagicMock()
    agent.extract = AsyncMock(return_value=steps)
    attack_mapper = MagicMock()
    attack_mapper.map_steps = AsyncMock(return_value=mappings)
    ctid, api = mapper_for(payload(steps, outcome_pi=True))
    service = CVEAnalysisService(
        Settings(ctid_only_mode=False, enable_ctid_mapping=False), graph, MagicMock(),
        agent, attack_mapper, ctid,
    )
    service._fetch_advisories = AsyncMock(return_value=([MagicMock()], [], []))
    disabled = await service.analyze(cve.cve_id, description_source="advisories")
    service.settings.enable_ctid_mapping = True
    enabled = await service.analyze(cve.cve_id, description_source="advisories")
    assert enabled.attack_chain == disabled.attack_chain == chain
    assert enabled.attack_mappings == disabled.attack_mappings == mappings
    assert enabled.exploit_steps == disabled.exploit_steps == steps
    assert graph.attack_candidates.await_count == 2 * len(steps)
    assert attack_mapper.map_steps.await_count == 2
    assert agent.extract.await_count == 2
    graph.description_attack_candidates.assert_not_awaited()
    api.chat.completions.create.assert_awaited_once()
    assert enabled.cve_level_attack_mappings.primary_impacts[0].mitre_technique_id is None


@pytest.mark.asyncio
async def test_coherent_sequence_reuses_primary_source_mapping_with_paraphrased_action():
    steps, mappings, chain = sources()
    data = payload(steps, outcome_pi=True)
    data["exploitation_techniques"][0]["action"] = "Deliver and trigger a crafted exploit request"
    data["exploitation_techniques"][0]["supporting_steps"] = [1, 2]
    ctid, _ = mapper_for(data)
    result = await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)
    assert result.exploitation_techniques[0].action == data["exploitation_techniques"][0]["action"]
    assert result.exploitation_techniques[0].mitre_technique_id == "T1190"
    assert result.exploitation_techniques[0].evidence_ids == [
        "existing-evidence-1", "existing-evidence-2"
    ]
    assert result.primary_impacts[0].enabled_by == ["ET-1"]
    assert result.secondary_impacts[0].enabled_by == ["PI-1"]


@pytest.mark.asyncio
async def test_explicit_source_step_disambiguates_identical_actions():
    steps, mappings, _ = sources()
    steps[1] = steps[1].model_copy(update={"action": steps[0].action})
    chain = attack_chain_from_mappings(steps, mappings)
    data = payload(steps, outcome_pi=True)
    ctid, _ = mapper_for(data)
    result = await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)
    assert result.exploitation_techniques[0].mitre_technique_id == "T1190"
    assert result.exploitation_techniques[0].mitre_tactic_id == "TA0001"


def test_internal_node_schema_has_only_user_requested_fields():
    from app.enrichment.ctid_mapper import CTID_SYSTEM_PROMPT, CTIDCausalNode

    assert set(CTIDCausalNode.model_fields) == {
        "id", "action", "enabled_by", "source_step", "supporting_steps", "reasoning"
    }
    assert "source_step" in CTID_SYSTEM_PROMPT
    assert "supporting_steps" in CTID_SYSTEM_PROMPT
    assert "Empty arrays are valid only when" in CTID_SYSTEM_PROMPT


@pytest.mark.parametrize("change", ["empty-support", "unknown-support", "source-not-supported"])
@pytest.mark.asyncio
async def test_requires_existing_supporting_steps_and_valid_source_reference(change):
    steps, mappings, chain = sources()
    data = payload(steps)
    et = data["exploitation_techniques"][0]
    if change == "empty-support":
        et["supporting_steps"] = []
    elif change == "unknown-support":
        et["supporting_steps"] = [404]
    else:
        et["source_step"] = 2
    ctid, _ = mapper_for(data)
    with pytest.raises(CTIDMappingError):
        await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)


@pytest.mark.asyncio
async def test_supporting_steps_may_be_shared_without_borrowing_mapping():
    steps, mappings, chain = sources()
    data = payload(steps, outcome_pi=True)
    data["secondary_impacts"] = [node("SI", 1, "Downstream consequence", ["PI-1"], None, [1])]
    ctid, _ = mapper_for(data)
    result = await ctid.map(CVERecord(cve_id="CVE-2026-33557"), steps, chain, mappings)
    assert result.exploitation_techniques[0].mitre_technique_id == "T1190"
    assert result.primary_impacts[0].mitre_technique_id is None
    assert result.secondary_impacts[0].mitre_technique_id is None
    assert result.primary_impacts[0].evidence_ids == result.secondary_impacts[0].evidence_ids


@pytest.mark.asyncio
async def test_sequence_et_with_no_primary_source_still_has_causal_nodes():
    steps, mappings, chain = sources()
    data = payload(steps, outcome_pi=True)
    data['exploitation_techniques'][0].update(
        action='Exploit through the supported request sequence',
        source_step=None,
        supporting_steps=[1, 2],
    )
    ctid, _ = mapper_for(data)
    result = await ctid.map(CVERecord(cve_id='CVE-2026-33557'), steps, chain, mappings)
    assert len(result.exploitation_techniques) == 1
    assert result.exploitation_techniques[0].mitre_technique_id is None
    assert result.primary_impacts[0].enabled_by == ['ET-1']
    assert result.secondary_impacts[0].enabled_by == ['PI-1']


@pytest.mark.parametrize('role', ['primary_impacts', 'secondary_impacts'])
@pytest.mark.asyncio
async def test_impacts_cannot_reuse_et_source_even_when_action_matches(role):
    steps, mappings, chain = sources()
    data = payload(steps)
    data[role][0].update(source_step=1, supporting_steps=[1], action=steps[0].action)
    ctid, _ = mapper_for(data)
    result = await ctid.map(CVERecord(cve_id='CVE-2026-33557'), steps, chain, mappings)
    impact = getattr(result, role)[0]
    assert impact.mitre_technique_id is None
    assert impact.mitre_tactic_id is None
    assert impact.confidence == 0.0
    assert impact.enabled_by == data[role][0]['enabled_by']
    assert impact.evidence_ids
    assert result.exploitation_techniques[0].mitre_technique_id == 'T1190'


@pytest.mark.asyncio
async def test_secondary_impact_cannot_reuse_primary_behavior_mapping():
    steps, mappings, chain = sources()
    data = payload(steps)
    data['secondary_impacts'][0].update(
        source_step=2, supporting_steps=[2], action=steps[1].action,
    )
    ctid, _ = mapper_for(data)
    result = await ctid.map(CVERecord(cve_id='CVE-2026-33557'), steps, chain, mappings)
    assert result.primary_impacts[0].mitre_technique_id == 'T1059'
    assert result.secondary_impacts[0].mitre_technique_id is None
    assert result.secondary_impacts[0].enabled_by == ['PI-1']


@pytest.mark.parametrize('role', ['primary_impacts', 'secondary_impacts'])
@pytest.mark.asyncio
async def test_summarized_outcomes_do_not_inherit_referenced_behavior_mapping(role):
    steps, mappings, chain = sources()
    data = payload(steps)
    data[role][0]['action'] = 'Security capability obtained as a consequence'
    ctid, _ = mapper_for(data)
    result = await ctid.map(CVERecord(cve_id='CVE-2026-33557'), steps, chain, mappings)
    impact = getattr(result, role)[0]
    assert impact.action == data[role][0]['action']
    assert impact.mitre_technique_id is None
    assert impact.mitre_tactic_id is None
    assert impact.evidence_ids


@pytest.mark.asyncio
async def test_distinct_behaviors_can_share_technique_ids_without_inheriting():
    steps, mappings, _ = sources()
    for mapping in mappings:
        mapping.mitre_technique_id = 'T1606'
        mapping.mitre_tactic_id = 'TA0006'
    chain = attack_chain_from_mappings(steps, mappings)
    ctid, _ = mapper_for(payload(steps))
    result = await ctid.map(CVERecord(cve_id='CVE-2026-33557'), steps, chain, mappings)
    for impact in [result.primary_impacts[0], result.secondary_impacts[0]]:
        assert impact.mitre_technique_id == 'T1606'
        assert impact.mitre_tactic_id == 'TA0006'
