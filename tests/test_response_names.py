from unittest.mock import AsyncMock, MagicMock

import pytest

from app.analysis import attack_chain_from_mappings
from app.api.response_names import resolve_attack_names
from app.api.routes import compact_analysis_view
from app.models import AttackMapping, CVEAnalysis, CVELevelAttackMapping, CVERecord, ExploitStep


@pytest.mark.asyncio
async def test_names_use_existing_ids_and_do_not_change_mapping_fields():
    step = ExploitStep.model_validate({
        'step': 1, 'action': 'Exploit the application',
        'evidence': [{'source_url': 'https://example.com/advisory',
                      'supporting_text': 'An attacker can exploit the application.'}],
    })
    mapping = AttackMapping(step=1, action=step.action, mitre_technique_id='T1190',
                            mitre_tactic_id='TA0001', reasoning='Existing mapping.',
                            confidence=0.8, evidence_ids=['ev-1'])
    analysis = CVEAnalysis(cve=CVERecord(cve_id='CVE-2026-33557'),
                           attack_chain=attack_chain_from_mappings([step], [mapping]),
                           attack_mappings=[mapping])
    analysis.cve_level_attack_mappings.exploitation_techniques = [CVELevelAttackMapping(
        id='ET-1', action=step.action, mitre_technique_id='T1190', mitre_tactic_id='TA0001',
        reasoning='Existing source.', confidence=0.8,
    )]
    analysis.cve_level_attack_mappings.primary_impacts = [CVELevelAttackMapping(
        id='PI-1', action='Access obtained', enabled_by=['ET-1'],
        reasoning='Outcome.', confidence=0.0,
    )]
    graph = MagicMock()
    graph.attack_names = AsyncMock(return_value={
        'T1190': 'Exploit Public-Facing Application', 'TA0001': 'Initial Access',
    })
    before = analysis.attack_chain[0].model_dump(exclude={'technique_name', 'tactic_name'})
    await resolve_attack_names([analysis], graph)
    graph.attack_names.assert_awaited_once_with(['T1190', 'TA0001'])
    assert analysis.attack_chain[0].model_dump(exclude={'technique_name', 'tactic_name'}) == before
    assert analysis.attack_mappings == [mapping]
    compact = compact_analysis_view(analysis).model_dump(mode='json')
    assert compact['attack_chain'][0]['technique_name'] == 'Exploit Public-Facing Application'
    assert compact['attack_chain'][0]['tactic_name'] == 'Initial Access'
    assert compact['ctid_map']['exploitation_techniques'][0]['tactic_name'] == 'Initial Access'
    assert compact['ctid_map']['primary_impacts'][0]['technique_name'] is None
    assert analysis.model_dump()['attack_chain'][0]['tactic_name'] == 'Initial Access'


@pytest.mark.asyncio
async def test_missing_ids_or_unknown_names_stay_null():
    analysis = CVEAnalysis(cve=CVERecord(cve_id='CVE-2026-57112'))
    graph = MagicMock()
    graph.attack_names = AsyncMock(return_value={})
    await resolve_attack_names([analysis], graph)
    graph.attack_names.assert_not_awaited()
    analysis.cve_level_attack_mappings.exploitation_techniques = [CVELevelAttackMapping(
        id='ET-1', action='Existing action', mitre_technique_id='T9999',
        mitre_tactic_id='TA9999', reasoning='Existing IDs.', confidence=0.5,
    )]
    await resolve_attack_names([analysis], graph)
    et = analysis.cve_level_attack_mappings.exploitation_techniques[0]
    assert et.technique_name is None and et.tactic_name is None
    assert et.mitre_technique_id == 'T9999' and et.mitre_tactic_id == 'TA9999'
