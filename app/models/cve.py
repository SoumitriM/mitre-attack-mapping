from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ReferenceCategory(StrEnum):
    VENDOR_ADVISORY = "vendor_advisory"
    RESEARCHER_ADVISORY = "researcher_advisory"
    EXPLOIT = "exploit"
    OTHER = "other"


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: HttpUrl
    source: str
    tags: list[str] = Field(default_factory=list)
    category: ReferenceCategory = ReferenceCategory.OTHER


class CVSSMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    base_score: float | None = None
    base_severity: str | None = None
    vector_string: str | None = None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None


class AffectedProduct(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor: str | None = None
    product: str | None = None
    versions: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    vulnerable_component: str | None = None


class SourceAttribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    url: HttpUrl
    retrieved_at: datetime


class CVERecord(BaseModel):
    """Normalized Phase 1 CVE representation. None means the source did not say."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    description: str | None = None
    affected_products: list[AffectedProduct] = Field(default_factory=list)
    cvss: CVSSMetrics | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    capec_ids: list[str] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    published_at: datetime | None = None
    updated_at: datetime | None = None
    sources: list[SourceAttribution] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    workarounds: list[str] = Field(default_factory=list)
    field_provenance: dict[str, list[str]] = Field(default_factory=dict)
