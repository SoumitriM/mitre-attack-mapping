import asyncio
import json

from app.enrichment.attack_mapper import FHGenieAttackMapper, evidence_id
from app.enrichment.fh_genie import AsyncCompatibleClient
from app.enrichment.validation_agent import FHGenieValidationAgent
from app.graph.repository import GraphRepository
from app.models import (
    AttackCandidate,
    CVEAttackBehaviorEnvelope,
    CVELevelAttackMapping,
    CVELevelAttackMappings,
    CVERecord,
    ExploitStep,
    MappingProcessingStatus,
)

CTID_PROMPT_VERSION = "ctid-cve-behaviors-v2"
CTID_SYSTEM_PROMPT = """
Apply the Center for Threat-Informed Defense CVE Mapping Methodology using only the supplied
exploit steps and exact evidence. Produce three conceptual arrays, not exactly three items.
exploitation_techniques contains independently evidenced methods used to exploit the vulnerability:
how exploitation occurs, not the benefit gained afterward. IDs are ET-1, ET-2, ...
primary_impacts contains immediate capabilities, benefits, or security consequences obtained
directly from successful exploitation. Do not duplicate an exploitation method merely because it
caused the impact. IDs are PI-1, PI-2, ...
secondary_impacts contains distinct downstream adversary behaviors causally enabled by one or more
primary impacts and directly supported by evidence. Not every post-exploitation observation
qualifies. IDs are SI-1, SI-2, ... and enabled_by must contain existing PI IDs.

Return zero or more independently evidenced items per array. Split compound behaviors when needed.
Do not infer behavior or causal links. Every item requires action, direct outcome, reasoning, and
evidence copied exactly from supplied steps. Only secondary impacts may populate enabled_by. Do not
select or mention ATT&CK IDs, tactics, CWE, CAPEC, CVSS, or vulnerability-specific examples.
Return JSON only: {"exploitation_techniques":[],"primary_impacts":[],"secondary_impacts":[]}.
Each item has exactly: id, action, prerequisites, outcome, enabled_by, evidence, reasoning.
""".strip()


class CTIDMappingError(ValueError):
    pass


def empty_ctid_mappings() -> CVELevelAttackMappings:
    return CVELevelAttackMappings()


class FHGenieCTIDCVEMapper:
    def __init__(self, model: str, client: AsyncCompatibleClient) -> None:
        self.model = model
        self._client = client

    async def identify_behaviors(
        self, cve: CVERecord, steps: list[ExploitStep]
    ) -> CVEAttackBehaviorEnvelope:
        payload = json.dumps({"cve_id": cve.cve_id, "exploit_steps": [
            item.model_dump(mode="json") for item in steps
        ]}, ensure_ascii=False)
        error: Exception | None = None
        correction = ""
        for _ in range(2):
            try:
                response = await self._client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "system", "content": CTID_SYSTEM_PROMPT + correction},
                              {"role": "user", "content": payload}],
                    temperature=0.0, max_completion_tokens=4096,
                    extra_body={"reasoning_split": True},
                )
                envelope = CVEAttackBehaviorEnvelope.model_validate_json(
                    response.choices[0].message.content or ""
                )
                self._verify_evidence(envelope, steps)
                return envelope
            except Exception as exc:
                error = exc
                correction = f"\nPrevious output invalid: {exc}. Return only schema-valid JSON."
        raise CTIDMappingError(f"CTID CVE behavior identification failed: {error}")

    async def map(self, cve: CVERecord, steps: list[ExploitStep], graph: GraphRepository,
                  mapper: FHGenieAttackMapper,
                  validator: FHGenieValidationAgent) -> CVELevelAttackMappings:
        envelope = await self.identify_behaviors(cve, steps)
        staged = [("exploitation_techniques", envelope.exploitation_techniques),
                  ("primary_impacts", envelope.primary_impacts),
                  ("secondary_impacts", envelope.secondary_impacts)]
        behaviors = [item for _, items in staged for item in items]
        synthetic = [ExploitStep(step=i, action=item.action,
                                 prerequisites=item.prerequisites, outcome=item.outcome,
                                 evidence=item.evidence)
                     for i, item in enumerate(behaviors, start=1)]
        platforms = sorted({p for product in cve.affected_products for p in product.platforms})
        retrieved = await asyncio.gather(
            *(graph.attack_candidates(item, platforms, cve_id=cve.cve_id)
              for item in synthetic), return_exceptions=True)
        candidates: dict[int, list[AttackCandidate]] = {}
        failures: set[int] = set()
        for step, result in zip(synthetic, retrieved, strict=True):
            if isinstance(result, BaseException):
                candidates[step.step] = []
                failures.add(step.step)
            else:
                candidates[step.step] = result
        mappable = [step for step in synthetic if step.step not in failures]
        proposals = await mapper.map_steps(cve, mappable, candidates) if mappable else []
        official = await graph.official_attack_context(
            [item.mitre_technique_id for item in proposals if item.mitre_technique_id])
        validated = await validator.validate(cve, mappable, proposals, official) if mappable else []
        checked = {item.step: item for item in validated}
        proposed = {item.step: item for item in proposals}
        result_groups: dict[str, list[CVELevelAttackMapping]] = {
            name: [] for name, _ in staged}
        index = 0
        for stage_name, items in staged:
            for behavior in items:
                index += 1
                validation = checked.get(index)
                retained = validation is not None and validation.proposed_technique_id is not None
                technique_id = validation.proposed_technique_id if validation else None
                tactic_id = validation.mitre_tactic_id if validation else None
                retained_evidence = validation.evidence_ids if validation else []
                status = (MappingProcessingStatus.RETRIEVAL_FAILED if index in failures
                          else MappingProcessingStatus.COMPLETED)
                proposal = proposed.get(index)
                if proposal and proposal.reasoning.startswith("Mapping rejected"):
                    status = MappingProcessingStatus.MAPPING_FAILED
                if validation and validation.validation.reasoning.startswith(
                    "Validation could not be completed:"
                ):
                    status = MappingProcessingStatus.VALIDATION_FAILED
                evidence_ids = [evidence_id(str(e.source_url), e.supporting_text)
                                for e in behavior.evidence]
                result_groups[stage_name].append(CVELevelAttackMapping(
                    id=behavior.id, action=behavior.action, enabled_by=behavior.enabled_by,
                    mitre_technique_id=(technique_id if retained else None),
                    mitre_tactic_id=(tactic_id if retained else None),
                    reasoning=(validation.validation.reasoning if validation else
                               "ATT&CK candidate retrieval failed for this behavior."),
                    confidence=(validation.validation.validator_confidence if validation else 0.0),
                    evidence_ids=(retained_evidence if retained else evidence_ids),
                    validation=(validation.validation if validation else None),
                    processing_status=status))
        return CVELevelAttackMappings.model_validate(result_groups)

    @staticmethod
    def _verify_evidence(envelope: CVEAttackBehaviorEnvelope,
                         steps: list[ExploitStep]) -> None:
        supplied = {(str(e.source_url), e.supporting_text) for step in steps for e in step.evidence}
        items = (envelope.exploitation_techniques + envelope.primary_impacts
                 + envelope.secondary_impacts)
        for behavior in items:
            for item in behavior.evidence:
                if (str(item.source_url), item.supporting_text) not in supplied:
                    raise CTIDMappingError("CTID behavior returned evidence not present in steps")
