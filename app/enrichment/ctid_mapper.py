import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from app.enrichment.attack_mapper import FHGenieAttackMapper, evidence_id
from app.enrichment.fh_genie import AsyncCompatibleClient
from app.enrichment.validation_agent import FHGenieValidationAgent
from app.graph.repository import GraphRepository
from app.models import (
    AttackCandidate,
    CVEAttackBehavior,
    CVEAttackBehaviorEnvelope,
    CVELevelAttackMapping,
    CVELevelAttackMappings,
    CVERecord,
    ExploitStep,
    MappingProcessingStatus,
)

CTID_PROMPT_VERSION = "ctid-cve-behaviors-v2"
CTID_LOG_DIR = Path("logs") / "fh-genie"
logger = logging.getLogger(__name__)
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
Use the minimum evidence objects needed to support each behavior, do not duplicate behaviors, and
keep action, outcome, and reasoning concise.
Return JSON only. The exact top-level schema is:
{"exploitation_techniques":[],"primary_impacts":[],"secondary_impacts":[]}.
Every behavior item must have exactly this structure:
{"id":"ET-1","action":"...","prerequisites":[],"outcome":"...","enabled_by":[],
"evidence":[{"source_url":"https://...","supporting_text":"exact supplied text"}],
"reasoning":"..."}
Evidence entries MUST be objects, never strings. Select them from EVIDENCE_CATALOG and copy
source_url and supporting_text exactly. Do not return evidence_id inside the evidence object.
""".strip()


class CTIDMappingError(ValueError):
    pass


def empty_ctid_mappings() -> CVELevelAttackMappings:
    return CVELevelAttackMappings()


@dataclass(frozen=True)
class BehaviorParseResult:
    envelope: CVEAttackBehaviorEnvelope
    errors: list[dict[str, object]]


def _behavior_count(result: BehaviorParseResult) -> int:
    envelope = result.envelope
    return sum(map(len, (
        envelope.exploitation_techniques,
        envelope.primary_impacts,
        envelope.secondary_impacts,
    )))


def _save_behavior_diagnostic(
    cve_id: str, content: str | None, result: BehaviorParseResult
) -> Path:
    CTID_LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
    path = CTID_LOG_DIR / f"{cve_id}_ctid_behavior_{timestamp}.json"
    counts = {
        "exploitation_techniques": len(result.envelope.exploitation_techniques),
        "primary_impacts": len(result.envelope.primary_impacts),
        "secondary_impacts": len(result.envelope.secondary_impacts),
    }
    valid_total = sum(counts.values())
    path.write_text(json.dumps({
        "cve_id": cve_id,
        "raw_model_response": content,
        "valid_behavior_counts": counts,
        "validation_errors": result.errors,
        "status": (
            "partial_validation_failure" if result.errors and valid_total
            else "validation_failed" if result.errors
            else "completed"
        ),
        "legitimate_empty_result": not result.errors and not any(counts.values()),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _save_behavior_failure(cve_id: str, content: str | None, error: Exception) -> Path:
    result = BehaviorParseResult(envelope=CVEAttackBehaviorEnvelope(), errors=[{
        "stage": "response", "error": str(error), "error_type": type(error).__name__
    }])
    return _save_behavior_diagnostic(cve_id, content, result)


class FHGenieCTIDCVEMapper:
    def __init__(self, model: str, client: AsyncCompatibleClient) -> None:
        self.model = model
        self._client = client

    async def identify_behaviors(
        self, cve: CVERecord, steps: list[ExploitStep]
    ) -> CVEAttackBehaviorEnvelope:
        catalog = [
            {
                "evidence_id": evidence_id(str(item.source_url), item.supporting_text),
                "source_url": str(item.source_url),
                "supporting_text": item.supporting_text,
            }
            for step in steps
            for item in step.evidence
        ]
        payload = json.dumps({
            "cve_id": cve.cve_id,
            "exploit_steps": [item.model_dump(mode="json") for item in steps],
            "EVIDENCE_CATALOG": catalog,
        }, ensure_ascii=False)
        error: Exception | None = None
        correction = ""
        best: BehaviorParseResult | None = None
        for attempt in range(2):
            content: str | None = None
            try:
                response = await self._client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "system", "content": CTID_SYSTEM_PROMPT + correction},
                              {"role": "user", "content": payload}],
                    temperature=0.0, max_completion_tokens=8192,
                    response_format={"type": "json_object"},
                    extra_body={"reasoning_split": True},
                )
                content = response.choices[0].message.content
                result = self._parse_behaviors(content, steps)
                log_file = _save_behavior_diagnostic(cve.cve_id, content, result)
                if result.errors:
                    logger.warning(
                        "CTID behavior response contained invalid behaviors",
                        extra={"cve_id": cve.cve_id, "log_file": str(log_file),
                               "invalid_behavior_count": len(result.errors)},
                    )
                    if best is None or _behavior_count(result) > _behavior_count(best):
                        best = result
                    if attempt == 0:
                        correction = (
                            "\nThe previous response contained these validation errors: "
                            f"{json.dumps(result.errors)}. Correct only the schema violations and "
                            "return the complete JSON object again."
                        )
                        continue
                return result.envelope
            except Exception as exc:
                error = exc
                log_file = _save_behavior_failure(cve.cve_id, content, exc)
                logger.warning(
                    "CTID behavior identification response failed validation",
                    extra={"cve_id": cve.cve_id, "log_file": str(log_file),
                           "error_type": type(exc).__name__, "error": str(exc)},
                )
                correction = f"\nPrevious output invalid: {exc}. Return only schema-valid JSON."
        if best is not None:
            return best.envelope
        raise CTIDMappingError(f"CTID CVE behavior identification failed: {error}")

    @classmethod
    def _parse_behaviors(
        cls, content: str | None, steps: list[ExploitStep]
    ) -> BehaviorParseResult:
        if not content:
            raise CTIDMappingError("empty CTID behavior-identification response")
        try:
            raw = json.loads(content)
        except json.JSONDecodeError as exc:
            raise CTIDMappingError(f"invalid CTID behavior JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise CTIDMappingError("CTID behavior response must be a JSON object")
        supplied = {(str(e.source_url), e.supporting_text) for step in steps for e in step.evidence}
        groups: dict[str, list[CVEAttackBehavior]] = {}
        errors: list[dict[str, object]] = []
        seen: set[str] = set()
        specs = (("exploitation_techniques", "ET-"),
                 ("primary_impacts", "PI-"), ("secondary_impacts", "SI-"))
        for field, prefix in specs:
            value = raw.get(field, [])
            if not isinstance(value, list):
                errors.append({"stage": field, "error": "stage must be an array"})
                groups[field] = []
                continue
            valid: list[CVEAttackBehavior] = []
            for index, item in enumerate(value):
                try:
                    behavior = CVEAttackBehavior.model_validate(item)
                    if not behavior.id.startswith(prefix) or behavior.id in seen:
                        raise ValueError("invalid or duplicate stage ID")
                    if field != "secondary_impacts" and behavior.enabled_by:
                        raise ValueError("only secondary impacts may populate enabled_by")
                    cls._verify_behavior_evidence(behavior, supplied)
                    seen.add(behavior.id)
                    valid.append(behavior)
                except (ValidationError, ValueError, CTIDMappingError) as exc:
                    errors.append({"stage": field, "index": index, "error": str(exc)})
            groups[field] = valid
        primary_ids = {item.id for item in groups["primary_impacts"]}
        retained_secondary: list[CVEAttackBehavior] = []
        for index, item in enumerate(groups["secondary_impacts"]):
            if item.enabled_by and set(item.enabled_by) <= primary_ids:
                retained_secondary.append(item)
            else:
                errors.append({"stage": "secondary_impacts", "index": index,
                               "error": "enabled_by does not reference retained primary impacts"})
        groups["secondary_impacts"] = retained_secondary
        return BehaviorParseResult(
            envelope=CVEAttackBehaviorEnvelope.model_validate(groups), errors=errors
        )

    @staticmethod
    def _verify_behavior_evidence(
        behavior: CVEAttackBehavior, supplied: set[tuple[str, str]]
    ) -> None:
        for item in behavior.evidence:
            if (str(item.source_url), item.supporting_text) not in supplied:
                raise CTIDMappingError("behavior evidence is absent from EVIDENCE_CATALOG")

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
        for step, candidate_result in zip(synthetic, retrieved, strict=True):
            if isinstance(candidate_result, BaseException):
                candidates[step.step] = []
                failures.add(step.step)
            else:
                candidates[step.step] = candidate_result
        mappable = [step for step in synthetic if step.step not in failures]
        mapping_results = await asyncio.gather(
            *(mapper.map_steps(cve, [step], {step.step: candidates[step.step]})
              for step in mappable),
            return_exceptions=True,
        )
        proposals = []
        mapping_failures: set[int] = set()
        for step, mapping_result in zip(mappable, mapping_results, strict=True):
            if isinstance(mapping_result, BaseException):
                mapping_failures.add(step.step)
            else:
                proposals.extend(mapping_result)
        official = await graph.official_attack_context(
            [item.mitre_technique_id for item in proposals if item.mitre_technique_id])
        proposal_by_step = {item.step: item for item in proposals}
        validation_inputs = [
            step for step in mappable
            if step.step not in mapping_failures and step.step in proposal_by_step
        ]
        validation_results = await asyncio.gather(
            *(validator.validate(cve, [step], [proposal_by_step[step.step]], official)
              for step in validation_inputs),
            return_exceptions=True,
        )
        validated = []
        validation_failures: set[int] = set()
        for step, validation_result in zip(
            validation_inputs, validation_results, strict=True
        ):
            if isinstance(validation_result, BaseException):
                validation_failures.add(step.step)
            else:
                validated.extend(validation_result)
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
                if index in mapping_failures:
                    status = MappingProcessingStatus.MAPPING_FAILED
                if index in validation_failures:
                    status = MappingProcessingStatus.VALIDATION_FAILED
                proposal = proposed.get(index)
                if proposal and proposal.reasoning.startswith("Mapping rejected"):
                    status = MappingProcessingStatus.MAPPING_FAILED
                if validation and validation.validation.reasoning.startswith(
                    "Validation could not be completed:"
                ):
                    status = MappingProcessingStatus.VALIDATION_FAILED
                evidence_ids = [evidence_id(str(e.source_url), e.supporting_text)
                                for e in behavior.evidence]
                failure_reason = {
                    MappingProcessingStatus.RETRIEVAL_FAILED:
                        "ATT&CK candidate retrieval failed for this behavior.",
                    MappingProcessingStatus.MAPPING_FAILED:
                        "ATT&CK mapping failed for this behavior.",
                    MappingProcessingStatus.VALIDATION_FAILED:
                        "ATT&CK validation failed for this behavior.",
                }.get(status, "No validated ATT&CK mapping was produced for this behavior.")
                result_groups[stage_name].append(CVELevelAttackMapping(
                    id=behavior.id, action=behavior.action, enabled_by=behavior.enabled_by,
                    mitre_technique_id=(technique_id if retained else None),
                    mitre_tactic_id=(tactic_id if retained else None),
                    reasoning=(validation.validation.reasoning if validation else failure_reason),
                    confidence=(validation.validation.validator_confidence if validation else 0.0),
                    evidence_ids=(retained_evidence if retained else evidence_ids),
                    validation=(validation.validation if validation else None),
                    processing_status=status))
        return CVELevelAttackMappings.model_validate(result_groups)
