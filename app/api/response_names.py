"""Add official display names after analysis, without altering mapping decisions."""

from app.graph.repository import GraphRepository
from app.models import CVEAnalysis, CVELevelAttackMapping, ValidatedAttackStep


async def resolve_attack_names(results: list[CVEAnalysis], graph: GraphRepository) -> None:
    nodes: list[ValidatedAttackStep | CVELevelAttackMapping] = []
    for result in results:
        nodes.extend(result.attack_chain)
        nodes.extend(result.cve_level_attack_mappings.exploitation_techniques)
        nodes.extend(result.cve_level_attack_mappings.primary_impacts)
        nodes.extend(result.cve_level_attack_mappings.secondary_impacts)
    identifiers = {
        identifier for node in nodes
        for identifier in (
            node.proposed_technique_id if isinstance(node, ValidatedAttackStep)
            else node.mitre_technique_id,
            node.mitre_tactic_id,
        ) if identifier is not None
    }
    names = await graph.attack_names(sorted(identifiers)) if identifiers else {}
    for node in nodes:
        technique_id = (
            node.proposed_technique_id if isinstance(node, ValidatedAttackStep)
            else node.mitre_technique_id
        )
        node.technique_name = names.get(technique_id) if technique_id else None
        node.tactic_name = names.get(node.mitre_tactic_id) if node.mitre_tactic_id else None
