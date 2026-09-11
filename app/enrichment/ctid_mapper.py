import asyncio
import json

from app.enrichment.attack_mapper import FHGenieAttackMapper, evidence_id
from app.enrichment.fh_genie import AsyncCompatibleClient
from app.enrichment.validation_agent import FHGenieValidationAgent
from app.graph.repository import GraphRepository
from app.models import (
    AttackCandidate,
    CVEAttackBehavior,
    CVEAttackBehaviorEnvelope,
    CVEAttackMappingCategory,
    CVELevelAttackMapping,
    CVERecord,
    ExploitStep,
)

CTID_PROMPT_VERSION = "ctid-cve-behaviors-v1"
CTID_SYSTEM_PROMPT = """
Apply the Center for Threat-Informed Defense CVE Mapping Methodology to one CVE using only the
supplied, already extracted exploit steps and their exact evidence. Identify exactly these three
categories in this order:
1. exploitation_technique: the method used to exploit the vulnerability;
2. primary_impact: the initial benefit gained through exploitation;
3. secondary_impact: what the adversary can do by gaining the primary impact.

This task identifies evidence-supported behaviors; it does not select ATT&CK techniques. Do not
use CWE, CAPEC, CVSS, vulnerability-type, or keyword lookup rules. Do not infer a generic impact,
future action, or post-exploitation behavior. A category may be unsupported. For an unsupported
category, return null action/outcome, empty prerequisites/evidence, and explain the missing support.
For a supported category, use a concise observable action and direct outcome, and copy one or more
evidence objects exactly from the supplied steps. Evidence must not be rewritten. The secondary
impact must be a distinct behavior enabled by the primary impact, not merely a restatement.
Return JSON only: {"behaviors":[{"category":"exploitation_technique","action":null,
"prerequisites":[],"outcome":null,"evidence":[],"reasoning":"..."},
{"category":"primary_impact","action":null,"prerequisites":[],"outcome":null,
"evidence":[],"reasoning":"..."},{"category":"secondary_impact","action":null,
"prerequisites":[],"outcome":null,"evidence":[],"reasoning":"..."}]}
""".strip()


class CTIDMappingError(ValueError):
    pass


def unmapped_ctid_mappings(reason: str) -> list[CVELevelAttackMapping]:
    return [
        CVELevelAttackMapping(category=category, reasoning=reason, confidence=0.0)
        for category in CVEAttackMappingCategory
    ]


class FHGenieCTIDCVEMapper:
    """Additive CVE-level CTID mapping stage using the existing retrieval and validation path."""

    def __init__(self, model: str, client: AsyncCompatibleClient) -> None:
        self.model = model
        self._client = client

    async def identify_behaviors(
        self, cve: CVERecord, steps: list[ExploitStep]
    ) -> list[CVEAttackBehavior]:
        payload = json.dumps(
            {
                "cve_id": cve.cve_id,
                "exploit_steps": [item.model_dump(mode="json") for item in steps],
            },
            ensure_ascii=False,
        )
        last_error: Exception | None = None
        for _ in range(2):
            try:
                response = await self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": CTID_SYSTEM_PROMPT},
                        {"role": "user", "content": payload},
                    ],
                    temperature=0.0,
                    max_completion_tokens=2048,
                    extra_body={"reasoning_split": True},
                )
                content = response.choices[0].message.content
                envelope = CVEAttackBehaviorEnvelope.model_validate_json(content or "")
                self._verify_evidence(envelope.behaviors, steps)
                return envelope.behaviors
            except Exception as exc:
                last_error = exc
        raise CTIDMappingError(f"CTID CVE behavior identification failed: {last_error}")

    async def map(
        self,
        cve: CVERecord,
        steps: list[ExploitStep],
        graph: GraphRepository,
        mapper: FHGenieAttackMapper,
        validator: FHGenieValidationAgent,
    ) -> list[CVELevelAttackMapping]:
        behaviors = await self.identify_behaviors(cve, steps)
        synthetic: list[ExploitStep] = []
        for number, behavior in enumerate(behaviors, start=1):
            if behavior.action is None:
                continue
            synthetic.append(
                ExploitStep(
                    step=number,
                    action=behavior.action,
                    prerequisites=behavior.prerequisites,
                    outcome=behavior.outcome or "",
                    evidence=behavior.evidence,
                )
            )

        platforms = sorted(
            {platform for product in cve.affected_products for platform in product.platforms}
        )
        candidate_lists = await asyncio.gather(
            *(graph.attack_candidates(item, platforms, cve_id=cve.cve_id) for item in synthetic),
            return_exceptions=True,
        )
        candidates: dict[int, list[AttackCandidate]] = {}
        retrieval_failures: dict[int, str] = {}
        for item, candidate_list in zip(synthetic, candidate_lists, strict=True):
            if isinstance(candidate_list, BaseException):
                candidates[item.step] = []
                retrieval_failures[item.step] = type(candidate_list).__name__
            else:
                candidates[item.step] = candidate_list
        proposals = await mapper.map_steps(cve, synthetic, candidates) if synthetic else []
        official = await graph.official_attack_context(
            [item.mitre_technique_id for item in proposals if item.mitre_technique_id]
        )
        validated = (
            await validator.validate(cve, synthetic, proposals, official) if synthetic else []
        )
        final_by_number = {item.step: item for item in validated}
        results: list[CVELevelAttackMapping] = []
        for number, behavior in enumerate(behaviors, start=1):
            checked = final_by_number.get(number)
            retained = checked is not None and checked.proposed_technique_id is not None
            technique_id = checked.proposed_technique_id if checked is not None else None
            tactic_id = checked.mitre_tactic_id if checked is not None else None
            retained_evidence = checked.evidence_ids if checked is not None else []
            behavior_evidence = [
                evidence_id(str(item.source_url), item.supporting_text)
                for item in behavior.evidence
            ]
            retrieval_failure = retrieval_failures.get(number)
            results.append(
                CVELevelAttackMapping(
                    category=behavior.category,
                    action=behavior.action,
                    mitre_technique_id=technique_id if retained else None,
                    mitre_tactic_id=tactic_id if retained else None,
                    reasoning=(
                        checked.validation.reasoning
                        if checked is not None
                        else (
                            f"ATT&CK candidate retrieval failed for this category: "
                            f"{retrieval_failure}"
                            if retrieval_failure
                            else behavior.reasoning
                        )
                    ),
                    confidence=(
                        checked.validation.validator_confidence
                        if checked is not None
                        else 0.0
                    ),
                    evidence_ids=retained_evidence if retained else behavior_evidence,
                    validation=checked.validation if checked is not None else None,
                )
            )
        return results

    @staticmethod
    def _verify_evidence(
        behaviors: list[CVEAttackBehavior], steps: list[ExploitStep]
    ) -> None:
        supplied = {
            (str(item.source_url), item.supporting_text)
            for step in steps
            for item in step.evidence
        }
        for behavior in behaviors:
            for item in behavior.evidence:
                if (str(item.source_url), item.supporting_text) not in supplied:
                    raise CTIDMappingError("CTID behavior returned evidence not present in steps")
