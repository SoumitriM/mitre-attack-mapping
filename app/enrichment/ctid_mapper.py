"""Organize existing attack-chain behaviors into CTID causal structure."""

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.enrichment.fh_genie import AsyncCompatibleClient
from app.enrichment.model_usage import save_model_usage
from app.models import (
    AttackMapping,
    CVELevelAttackMapping,
    CVELevelAttackMappings,
    CVERecord,
    ExploitStep,
    ValidatedAttackStep,
)

CTID_LOG_DIR = Path("logs") / "fh-genie"
CTID_PROMPT_VERSION = "ctid-chain-causality-v2"
logger = logging.getLogger(__name__)

CTID_SYSTEM_PROMPT = """
Transform the supplied attack chain into CTID causal structure.

Existing attack-chain ATT&CK mappings are the source of truth. Do not generate, validate,
rerank, replace, or infer ATT&CK techniques or tactics. Python will copy existing
technique/tactic IDs.

Return:

- `exploitation_techniques`: behaviors or coherent step sequences that enable exploitation
- `primary_impacts`: immediate security consequences or capabilities enabled by ETs
- `secondary_impacts`: downstream consequences enabled by PIs

Rules:

- ATT&CK mapping is not required for a step to become ET, PI, or SI.
- Preserve distinct exploitation paths.
- PI/SI may summarize evidenced outcomes.
- Do not invent unsupported behaviors or consequences.
- Preserve ET -> PI -> SI causality.
- Empty output is valid only when the chain contains no supported exploitation behavior
  or consequence.
- Return JSON only.

Schema:
{
  "exploitation_techniques": [
    {
      "id": "ET-1",
      "action": "string",
      "enabled_by": []
    }
  ],
  "primary_impacts": [
    {
      "id": "PI-1",
      "action": "string",
      "enabled_by": ["ET-1"]
    }
  ],
  "secondary_impacts": [
    {
      "id": "SI-1",
      "action": "string",
      "enabled_by": ["PI-1"]
    }
  ]
}
""".strip()


class CTIDMappingError(ValueError):
    pass


def empty_ctid_mappings() -> CVELevelAttackMappings:
    return CVELevelAttackMappings()


class CTIDCausalNode(BaseModel):
    """The user-supplied causal schema; external response fields remain unchanged."""

    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(pattern=r"^(ET|PI|SI)-[1-9][0-9]*$")
    action: str = Field(min_length=1)
    enabled_by: list[str]


class CTIDCausalEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    exploitation_techniques: list[CTIDCausalNode]
    primary_impacts: list[CTIDCausalNode]
    secondary_impacts: list[CTIDCausalNode]

    @model_validator(mode="after")
    def valid_references(self) -> "CTIDCausalEnvelope":
        """Validate graph shape and foreign keys, without judging ATT&CK semantics."""
        groups: tuple[tuple[str, list[CTIDCausalNode], set[str]], ...] = (
            ("ET", self.exploitation_techniques, set()),
            ("PI", self.primary_impacts, {node.id for node in self.exploitation_techniques}),
            ("SI", self.secondary_impacts, {node.id for node in self.primary_impacts}),
        )
        ids: set[str] = set()
        for prefix, nodes, predecessors in groups:
            for node in nodes:
                if not node.id.startswith(f"{prefix}-") or node.id in ids:
                    raise ValueError("CTID IDs must be unique and match their category")
                ids.add(node.id)
                if prefix == "ET":
                    if node.enabled_by:
                        raise ValueError("ET must have no enabled_by links")
                elif not node.enabled_by or not set(node.enabled_by) <= predecessors:
                    raise ValueError("PI must reference ET nodes; SI must reference PI nodes")
        return self


class FHGenieCTIDCVEMapper:
    def __init__(self, model: str, client: AsyncCompatibleClient) -> None:
        self.model = model
        self._client = client

    async def identify_behaviors(
        self,
        cve: CVERecord,
        steps: list[ExploitStep],
        attack_chain: list[ValidatedAttackStep],
        attack_mappings: list[AttackMapping],
    ) -> CTIDCausalEnvelope:
        """One causal-classification call; no ATT&CK selection or mapping calls."""
        payload = {
            "cve_id": cve.cve_id,
            "exploit_steps": [item.model_dump(mode="json") for item in steps],
            "attack_chain": [item.model_dump(mode="json") for item in attack_chain],
            "attack_mappings": [item.model_dump(mode="json") for item in attack_mappings],
        }
        content: str | None = None
        error: str | None = None
        try:
            response = await self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": CTID_SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
                ],
                temperature=0.0,
                max_completion_tokens=4096,
                response_format={"type": "json_object"},
                extra_body={"reasoning_split": True},
            )
            save_model_usage("ctid_identification", self.model, response, cve_id=cve.cve_id)
            content = response.choices[0].message.content
            if not content:
                raise CTIDMappingError("empty CTID causal response")
            normalized = content.strip()
            if normalized.startswith("```") and normalized.endswith("```"):
                normalized = re.sub(r"^```(?:json)?\s*", "", normalized, count=1)
                normalized = re.sub(r"\s*```$", "", normalized, count=1)
            return CTIDCausalEnvelope.model_validate_json(normalized)
        except (ValidationError, CTIDMappingError) as exc:
            error = str(exc)
            raise CTIDMappingError(f"invalid CTID causal structure: {exc}") from exc
        except Exception as exc:
            error = str(exc)
            raise CTIDMappingError(f"CTID causal classification failed: {exc}") from exc
        finally:
            self._save_diagnostic(cve.cve_id, content, error)

    @staticmethod
    def _save_diagnostic(cve_id: str, content: str | None, error: str | None) -> None:
        try:
            CTID_LOG_DIR.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
            path = CTID_LOG_DIR / f"{cve_id}_ctid_behavior_{timestamp}.json"
            path.write_text(json.dumps({
                "cve_id": cve_id,
                "prompt_version": CTID_PROMPT_VERSION,
                "raw_model_response": content,
                "validation_error": error,
                "status": "validation_failed" if error else "completed",
            }, indent=2), encoding="utf-8")
        except OSError:
            logger.exception("Failed to write CTID diagnostic")

    async def map(
        self,
        cve: CVERecord,
        steps: list[ExploitStep],
        attack_chain: list[ValidatedAttackStep],
        attack_mappings: list[AttackMapping],
    ) -> CVELevelAttackMappings:
        """Structure existing results and copy mappings; never remap a CTID node."""
        if not attack_chain:
            return empty_ctid_mappings()
        envelope = await self.identify_behaviors(cve, steps, attack_chain, attack_mappings)

        def convert(node: CTIDCausalNode) -> CVELevelAttackMapping:
            # Exact action identity only: no semantic matching or technique selection.
            # Summaries and ambiguous matches retain null IDs.
            matches = [item for item in attack_chain if item.action == node.action]
            source = matches[0] if len(matches) == 1 else None
            return CVELevelAttackMapping(
                id=node.id,
                action=node.action,
                enabled_by=node.enabled_by,
                mitre_technique_id=source.proposed_technique_id if source else None,
                mitre_tactic_id=source.mitre_tactic_id if source else None,
                reasoning=(
                    source.validation.reasoning if source else
                    "CTID summary of the supplied attack chain; no existing mapping reused."
                ),
                confidence=source.validation.validator_confidence if source else 0.0,
                evidence_ids=list(source.evidence_ids) if source else [],
            )

        return CVELevelAttackMappings(
            exploitation_techniques=[convert(node) for node in envelope.exploitation_techniques],
            primary_impacts=[convert(node) for node in envelope.primary_impacts],
            secondary_impacts=[convert(node) for node in envelope.secondary_impacts],
        )
