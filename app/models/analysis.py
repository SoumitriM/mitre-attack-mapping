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


class CVEAnalysis(BaseModel):
    cve: CVERecord
    advisories: list[AdvisoryResult] = Field(default_factory=list)
    exploit_steps: list[ExploitStep] = Field(default_factory=list)
    subgraph: EvidenceSubgraph = Field(default_factory=EvidenceSubgraph)
    warnings: list[str] = Field(default_factory=list)
