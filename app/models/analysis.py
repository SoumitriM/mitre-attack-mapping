from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from app.models.cve import CVERecord


class SelectionReason(StrEnum):
    PRIORITY_TAG = "priority_tag"
    ALLOWLIST = "allowlist"
    PRIORITY_TAG_AND_ALLOWLIST = "priority_tag_and_allowlist"


class ExtractionStatus(StrEnum):
    COMPLETED = "completed"
    FETCH_FAILED = "fetch_failed"
    UNSUPPORTED_CONTENT = "unsupported_content"
    EXTRACTION_FAILED = "extraction_failed"


class AdvisoryResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: HttpUrl
    reference_tags: list[str] = Field(default_factory=list)
    selection_reason: SelectionReason
    retrieved_at: datetime | None = None
    checksum: str | None = None
    extraction_status: ExtractionStatus


class DescriptionEvidenceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_name: str
    source_url: HttpUrl
    extraction_status: ExtractionStatus


class StepEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_url: HttpUrl
    supporting_text: str = Field(min_length=1)


class ExploitStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step: int = Field(ge=1)
    action: str = Field(min_length=1)
    prerequisites: list[str] = Field(default_factory=list)
    outcome: str = Field(min_length=1)
    evidence: list[StepEvidence] = Field(min_length=1)


class ExploitStepEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    steps: list[ExploitStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def sequential_steps(self) -> "ExploitStepEnvelope":
        if [item.step for item in self.steps] != list(range(1, len(self.steps) + 1)):
            raise ValueError("exploit steps must be sequential starting at 1")
        return self


class GroundingResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    supported: bool
    confidence: float = Field(ge=0, le=1)
    reasoning: str = Field(min_length=1)


class AttackCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mitre_technique_id: str
    name: str
    description: str
    platforms: list[str] = Field(default_factory=list)
    tactics: dict[str, str] = Field(default_factory=dict)


class AttackMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step: int = Field(ge=1)
    action: str = Field(min_length=1)
    mitre_technique_id: str | None = None
    mitre_tactic_id: str | None = None
    reasoning: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def ids_are_both_present_or_absent(self) -> "AttackMapping":
        if (self.mitre_technique_id is None) != (self.mitre_tactic_id is None):
            raise ValueError("technique and tactic IDs must both be present or null")
        if self.mitre_technique_id is None and self.confidence > 0.33:
            raise ValueError("unmapped steps must have low confidence")
        if self.mitre_technique_id is not None and not self.evidence_ids:
            raise ValueError("mapped steps require evidence IDs")
        return self


class AttackMappingEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mappings: list[AttackMapping]


class ValidationStatus(StrEnum):
    VALIDATED = "validated"
    UNMAPPED = "unmapped"


class ValidationChecks(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_exists: bool
    tactic_valid: bool
    platform_compatible: bool
    evidence_support: bool
    semantic_match: bool


class ValidationDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: ValidationStatus
    checks: ValidationChecks
    reasoning: str = Field(min_length=1)
    validator_confidence: float = Field(ge=0, le=1)


class ValidatedAttackStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step: int = Field(ge=1)
    action: str = Field(min_length=1)
    proposed_technique_id: str | None = None
    mitre_tactic_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    validation: ValidationDetails

    @model_validator(mode="after")
    def validated_mapping_is_consistent(self) -> "ValidatedAttackStep":
        if (self.proposed_technique_id is None) != (self.mitre_tactic_id is None):
            raise ValueError("technique and tactic IDs must both be present or null")
        if self.validation.status == ValidationStatus.VALIDATED:
            if self.proposed_technique_id is None or not self.evidence_ids:
                raise ValueError("validated steps require ATT&CK IDs and evidence IDs")
        elif self.proposed_technique_id is not None or self.validation.validator_confidence > 0.33:
            raise ValueError("unmapped steps require null IDs and low confidence")
        return self


class ValidationEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    steps: list[ValidatedAttackStep] = Field(min_length=1, max_length=1)


class GraphNode(BaseModel):
    id: str
    type: str
    properties: dict[str, object] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    relationship: str
    target: str
    authoritative: bool = True


class EvidenceSubgraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class PresentationProvenance(StrEnum):
    AUTHORITATIVE = "authoritative"
    ADVISORY_DERIVED = "advisory_derived"
    LLM_INFERRED = "llm_inferred"


class PresentationNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    label: str
    provenance: PresentationProvenance
    properties: dict[str, object] = Field(default_factory=dict)


class PresentationEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    relationship: str
    provenance: PresentationProvenance
    properties: dict[str, object] = Field(default_factory=dict)


class AttackChainGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    nodes: list[PresentationNode] = Field(default_factory=list)
    edges: list[PresentationEdge] = Field(default_factory=list)
    legend: dict[str, str] = Field(
        default_factory=lambda: {
            "authoritative": "Official CVE/CWE/CAPEC/ATT&CK relationship",
            "advisory_derived": "Exploit behavior extracted from advisory evidence",
            "llm_inferred": "ATT&CK mapping proposed by an LLM and independently validated",
        }
    )


class CVEAnalysis(BaseModel):
    cve: CVERecord
    description_evidence: DescriptionEvidenceResult | None = None
    advisories: list[AdvisoryResult] = Field(default_factory=list)
    exploit_steps: list[ExploitStep] = Field(default_factory=list)
    attack_mappings: list[AttackMapping] = Field(default_factory=list)
    attack_chain: list[ValidatedAttackStep] = Field(default_factory=list)
    subgraph: EvidenceSubgraph = Field(default_factory=EvidenceSubgraph)
    warnings: list[str] = Field(default_factory=list)
