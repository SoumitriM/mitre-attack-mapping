from datetime import UTC, datetime
from typing import Any

from app.models import (
    AffectedProduct,
    CVERecord,
    CVSSMetrics,
    Reference,
    ReferenceCategory,
    SourceAttribution,
)


def _parse_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def _english(items: list[dict[str, Any]]) -> str | None:
    return next((item.get("value") for item in items if item.get("lang") == "en"), None)


def _category(tags: list[str]) -> ReferenceCategory:
    lowered = {tag.lower() for tag in tags}
    if lowered & {"exploit", "exploit-db", "third party advisory"}:
        return (
            ReferenceCategory.EXPLOIT
            if "exploit" in lowered
            else ReferenceCategory.RESEARCHER_ADVISORY
        )
    if "vendor advisory" in lowered:
        return ReferenceCategory.VENDOR_ADVISORY
    return ReferenceCategory.OTHER


def _cvss_from_nvd(cve: dict[str, Any]) -> CVSSMetrics | None:
    metrics = cve.get("metrics", {})
    candidates = (
        metrics.get("cvssMetricV40", [])
        or metrics.get("cvssMetricV31", [])
        or metrics.get("cvssMetricV30", [])
        or metrics.get("cvssMetricV2", [])
    )
    if not candidates:
        return None
    metric = candidates[0]
    data = metric.get("cvssData", {})
    return CVSSMetrics(
        version=str(data.get("version", "unknown")),
        base_score=data.get("baseScore"),
        base_severity=data.get("baseSeverity") or metric.get("baseSeverity"),
        vector_string=data.get("vectorString"),
        attack_vector=data.get("attackVector") or data.get("accessVector"),
        attack_complexity=data.get("attackComplexity") or data.get("accessComplexity"),
        privileges_required=data.get("privilegesRequired") or data.get("authentication"),
        user_interaction=data.get("userInteraction"),
        scope=data.get("scope"),
        confidentiality_impact=data.get("confidentialityImpact"),
        integrity_impact=data.get("integrityImpact"),
        availability_impact=data.get("availabilityImpact"),
    )


def normalize(cve_id: str, cve_org: dict[str, Any] | None, nvd: dict[str, Any] | None) -> CVERecord:
    cna = ((cve_org or {}).get("containers") or {}).get("cna", {})
    nvd_cve = (((nvd or {}).get("vulnerabilities") or [{}])[0]).get("cve", {}) if nvd else {}
    description = _english(nvd_cve.get("descriptions", [])) or _english(cna.get("descriptions", []))

    products: list[AffectedProduct] = []
    for affected in cna.get("affected", []):
        versions = [
            str(version.get("version"))
            for version in affected.get("versions", [])
            if version.get("status") == "affected" and version.get("version")
        ]
        products.append(
            AffectedProduct(
                vendor=affected.get("vendor"),
                product=affected.get("product"),
                versions=versions,
                platforms=affected.get("platforms", []),
                vulnerable_component=affected.get("packageName") or affected.get("module"),
            )
        )

    weaknesses = nvd_cve.get("weaknesses", [])
    cwe_ids = {
        desc.get("value")
        for weakness in weaknesses
        for desc in weakness.get("description", [])
        if str(desc.get("value", "")).startswith("CWE-")
    }
    for problem in cna.get("problemTypes", []):
        for desc in problem.get("descriptions", []):
            if str(desc.get("cweId", "")).startswith("CWE-"):
                cwe_ids.add(desc["cweId"])

    references_by_url: dict[str, Reference] = {}
    raw_references = [*cna.get("references", []), *nvd_cve.get("references", [])]
    for raw in raw_references:
        if not raw.get("url"):
            continue
        tags = list(dict.fromkeys(raw.get("tags", [])))
        url = str(raw["url"])
        references_by_url[url] = Reference(
            url=url, source=raw.get("source", "CVE.org"), tags=tags, category=_category(tags)
        )

    capec_ids = {
        value
        for value in [*(cwe_ids or set())]
        if str(value).startswith("CAPEC-")
    }
    cwe_ids = {value for value in cwe_ids if value and str(value).startswith("CWE-")}
    now = datetime.now(UTC)
    sources = []
    if cve_org:
        sources.append(
            SourceAttribution(
                name="CVE.org", url=f"https://www.cve.org/CVERecord?id={cve_id}", retrieved_at=now
            )
        )
    if nvd:
        sources.append(
            SourceAttribution(
                name="NVD", url=f"https://nvd.nist.gov/vuln/detail/{cve_id}", retrieved_at=now
            )
        )
    metadata = (cve_org or {}).get("cveMetadata", {})
    return CVERecord(
        cve_id=cve_id,
        description=description,
        affected_products=products,
        cvss=_cvss_from_nvd(nvd_cve),
        cwe_ids=sorted(cwe_ids),
        capec_ids=sorted(capec_ids),
        references=list(references_by_url.values()),
        published_at=_parse_datetime(nvd_cve.get("published") or metadata.get("datePublished")),
        updated_at=_parse_datetime(nvd_cve.get("lastModified") or metadata.get("dateUpdated")),
        sources=sources,
    )
