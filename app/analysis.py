import asyncio
import logging
from datetime import UTC, datetime
from typing import Literal

import httpx

from app.advisory.client import (
    AdvisoryClient,
    FetchedAdvisory,
    UnsupportedAdvisoryContent,
    select_references,
)
from app.advisory.compression import MAX_SUCCESSFUL_ADVISORIES, advisory_priority
from app.config import Settings
from app.enrichment.attack_mapper import FHGenieAttackMapper, MappingResponseError
from app.enrichment.ctid_mapper import (
    CTIDMappingError,
    FHGenieCTIDCVEMapper,
    empty_ctid_mappings,
)
from app.enrichment.fh_genie import (
    ExtractionResponseError,
    FHGenieEvidenceAgent,
    normalized_description_evidence,
)
from app.graph.repository import GraphRepository, GraphUnavailable
from app.ingestion.description import description_has_exploit_behavior
from app.ingestion.opencve import fetch_opencve_description
from app.ingestion.service import CVEIngestionService, normalize_cve_id
from app.models import (
    AdvisoryResult,
    AttackCandidate,
    AttackMapping,
    CVEAnalysis,
    CVERecord,
    DescriptionEvidenceResult,
    EvidenceSubgraph,
    ExploitStep,
    ExtractionStatus,
    SourceAttribution,
    ValidatedAttackStep,
    ValidationChecks,
    ValidationDetails,
    ValidationStatus,
)

logger = logging.getLogger(__name__)


def attack_chain_from_mappings(
    steps: list[ExploitStep],
    mappings: list[AttackMapping],
) -> list[ValidatedAttackStep]:
    """Present mapping output directly without a second semantic judgment stage."""
    by_step = {item.step: item for item in mappings}
    chain: list[ValidatedAttackStep] = []
    for step in steps:
        mapping = by_step.get(step.step)
        mapped = mapping is not None and mapping.mitre_technique_id is not None
        technique_id = mapping.mitre_technique_id if mapping and mapped else None
        tactic_id = mapping.mitre_tactic_id if mapping and mapped else None
        evidence_ids = mapping.evidence_ids if mapping and mapped else []
        confidence = mapping.confidence if mapping and mapped else 0.0
        chain.append(
            ValidatedAttackStep(
                step=step.step,
                action=step.action,
                proposed_technique_id=technique_id,
                mitre_tactic_id=tactic_id,
                evidence_ids=evidence_ids,
                validation=ValidationDetails(
                    status=(ValidationStatus.MAPPED if mapped else ValidationStatus.UNMAPPED),
                    checks=ValidationChecks(
                        technique_exists=mapped,
                        tactic_valid=mapped,
                        platform_compatible=mapped,
                        evidence_support=mapped,
                        semantic_match=False,
                    ),
                    reasoning=(
                        mapping.reasoning
                        if mapping is not None
                        else "No ATT&CK mapping satisfied the configured mapping threshold."
                    ),
                    validator_confidence=confidence,
                ),
            )
        )
    return chain


class CVEAnalysisService:
    def __init__(
        self,
        settings: Settings,
        graph: GraphRepository,
        client: httpx.AsyncClient,
        agent: FHGenieEvidenceAgent | None = None,
        mapper: FHGenieAttackMapper | None = None,
        ctid_mapper: FHGenieCTIDCVEMapper | None = None,
    ) -> None:
        self.settings = settings
        self.graph = graph
        self.client = client
        self.agent = agent
        self.mapper = mapper
        self.ctid_mapper = ctid_mapper

    async def analyze_opencve(self, cve_id: str) -> CVEAnalysis:
        """Use only OpenCVE description evidence; skip advisories and compression."""
        return await self.analyze(cve_id, description_source="opencve")

    async def analyze(
        self, cve_id: str, *, description_source: Literal["auto", "advisories", "opencve"] = "auto"
    ) -> CVEAnalysis:
        if description_source == "opencve" and self.settings.ctid_only_mode:
            raise ValueError("OpenCVE extraction requires ctid_only_mode=False")
        normalized_id = normalize_cve_id(cve_id)
        await self.graph.verify_taxonomy()
        cve = await CVEIngestionService(self.settings, self.client).analyze(normalized_id)
        if self.settings.ctid_only_mode:
            return await self._analyze_ctid_only(cve)
        fetched: list[FetchedAdvisory] = []
        results: list[AdvisoryResult] = []
        warnings = list(cve.warnings)
        description = normalized_description_evidence(cve)
        if description_source in {"auto", "opencve"}:
            try:
                description = await fetch_opencve_description(cve.cve_id, self.client)
            except (httpx.HTTPError, ValueError) as exc:
                if description_source == "opencve":
                    raise
                warnings.append(
                    f"OpenCVE description unavailable ({type(exc).__name__}); "
                    "using authoritative description"
                )
            else:
                cve = cve.model_copy(deep=True)
                cve.description = description.text
                cve.field_provenance["description"] = ["OpenCVE"]
                cve.sources.append(
                    SourceAttribution(
                        name="OpenCVE", url=description.source_url, retrieved_at=datetime.now(UTC)
                    )
                )
        description_result = (
            DescriptionEvidenceResult(
                source_name=description.source_name,
                source_url=description.source_url,
                extraction_status=ExtractionStatus.COMPLETED,
            )
            if description
            else None
        )
        use_advisories = description_source == "advisories" or (
            description_source == "auto"
            and not description_has_exploit_behavior(description.text if description else None)
        )
        if use_advisories:
            if description_source == "auto":
                warnings.append("Description lacks a concrete exploit mechanism; using advisories")
            fetched, results, advisory_warnings = await self._fetch_advisories(cve)
            warnings.extend(advisory_warnings)

        steps: list[ExploitStep] = []
        if not (fetched or description):
            warnings.append("No trusted description or advisory evidence was available")
        elif description_source == "auto" and use_advisories and not fetched:
            warnings.append(
                "No advisory evidence was retrieved and the description is insufficient; "
                "extraction was skipped"
            )
            self._mark_extraction_failed(description_result, results)
        elif self.agent is None:
            warnings.append(
                "The selected inference provider is not configured; "
                "exploit-step extraction was skipped"
            )
            self._mark_extraction_failed(description_result, results)
        else:
            try:
                steps = await self.agent.extract(cve.cve_id, fetched, description)
                if description_source == "auto" and not use_advisories and not steps:
                    warnings.append(
                        "Description extraction returned no steps; trying advisory evidence"
                    )
                    fetched, results, advisory_warnings = await self._fetch_advisories(cve)
                    warnings.extend(advisory_warnings)
                    # A second extraction uses newly retrieved evidence. Never repeat
                    # the same description-only request if no advisory was fetched.
                    if fetched:
                        steps = await self.agent.extract(cve.cve_id, fetched, description)
            except ExtractionResponseError as exc:
                warnings.append(str(exc))
                self._mark_extraction_failed(description_result, results)
        if description_source == "auto" and not steps:
            warnings.append("No exploit steps were extracted from the available evidence")

        mappings: list[AttackMapping] = []
        if steps and self.mapper is None:
            warnings.append("FH Genie ATT&CK mapper is not configured")
        elif steps and self.mapper is not None:
            candidate_lists = await asyncio.gather(
                *(
                    self.graph.attack_candidates(
                        step,
                        cve_id=cve.cve_id,
                    )
                    for step in steps
                ),
                return_exceptions=True,
            )
            candidates: dict[int, list[AttackCandidate]] = {}
            for step, candidate_list in zip(steps, candidate_lists, strict=True):
                if isinstance(candidate_list, BaseException):
                    warnings.append(
                        f"ATT&CK candidate retrieval failed for step {step.step}: "
                        f"{type(candidate_list).__name__}"
                    )
                    candidates[step.step] = []
                else:
                    candidates[step.step] = candidate_list
            try:
                mappings = await self.mapper.map_steps(cve, steps, candidates)
            except MappingResponseError as exc:
                warnings.append(str(exc))
        attack_chain = attack_chain_from_mappings(steps, mappings) if steps else []
        cve_level_mappings = empty_ctid_mappings()
        if not self.settings.enable_ctid_mapping:
            logger.info(
                "CTID mapping skipped",
                extra={"cve_id": cve.cve_id, "ctid_skipped": True},
            )
        elif steps and (self.ctid_mapper is None or self.mapper is None):
            warnings.append("FH Genie CTID CVE-level mapper is not configured")
            cve_level_mappings = empty_ctid_mappings()
        elif steps and self.ctid_mapper and self.mapper:
            try:
                cve_level_mappings = await self.ctid_mapper.map(
                    cve, steps, self.graph, self.mapper
                )
            except (CTIDMappingError, GraphUnavailable) as exc:
                logger.exception(
                    "CVE-level CTID mapping failed",
                    extra={"cve_id": cve.cve_id, "stage": "cve_level_attack_mappings"},
                )
                warnings.append(f"CVE-level CTID mapping failed: {exc}")
                cve_level_mappings = empty_ctid_mappings()
        return CVEAnalysis(
            cve=cve,
            description_evidence=description_result,
            advisories=sorted(results, key=lambda item: str(item.url)),
            exploit_steps=steps,
            attack_mappings=mappings,
            attack_chain=attack_chain,
            cve_level_attack_mappings=cve_level_mappings,
            subgraph=EvidenceSubgraph(),
            warnings=list(dict.fromkeys(warnings)),
        )

    async def _fetch_advisories(
        self, cve: CVERecord
    ) -> tuple[list[FetchedAdvisory], list[AdvisoryResult], list[str]]:
        selected = sorted(
            select_references(cve.references, self.settings.advisory_allowed_domains),
            key=advisory_priority,
        )
        client = AdvisoryClient(self.client, max_bytes=self.settings.advisory_max_bytes)
        fetched: list[FetchedAdvisory] = []
        results: list[AdvisoryResult] = []
        warnings: list[str] = []
        for reference in selected:
            try:
                advisory = await client.fetch(reference)
            except Exception as exc:
                results.append(
                    AdvisoryResult(
                        url=reference.reference.url,
                        reference_tags=reference.reference.tags,
                        selection_reason=reference.reason,
                        extraction_status=(
                            ExtractionStatus.UNSUPPORTED_CONTENT
                            if isinstance(exc, UnsupportedAdvisoryContent)
                            else ExtractionStatus.FETCH_FAILED
                        ),
                    )
                )
                warnings.append(f"Advisory unavailable: {reference.reference.url}")
            else:
                fetched.append(advisory)
                results.append(
                    AdvisoryResult(
                        url=advisory.selected.reference.url,
                        reference_tags=advisory.selected.reference.tags,
                        selection_reason=advisory.selected.reason,
                        retrieved_at=advisory.retrieved_at,
                        checksum=advisory.checksum,
                        extraction_status=ExtractionStatus.COMPLETED,
                    )
                )
                if len(fetched) == MAX_SUCCESSFUL_ADVISORIES:
                    break
        return fetched, results, warnings

    @staticmethod
    def _mark_extraction_failed(
        description: DescriptionEvidenceResult | None, advisories: list[AdvisoryResult]
    ) -> None:
        if description:
            description.extraction_status = ExtractionStatus.EXTRACTION_FAILED
        for advisory in advisories:
            if advisory.extraction_status == ExtractionStatus.COMPLETED:
                advisory.extraction_status = ExtractionStatus.EXTRACTION_FAILED

    async def _analyze_ctid_only(self, cve: CVERecord) -> CVEAnalysis:
        mappings = empty_ctid_mappings()
        warnings = list(cve.warnings)
        if not cve.description:
            warnings.append("CVE description was unavailable; CTID mapping was skipped")
        elif self.ctid_mapper is None:
            raise CTIDMappingError("FH Genie CTID mapper is not configured")
        else:
            description = normalized_description_evidence(cve)
            source_url = (
                description.source_url
                if description
                else f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"
            )
            try:
                normalized = await self.ctid_mapper.normalize_description(cve)
                candidates = await self.graph.description_attack_candidates(
                    cve.cve_id, normalized.model_dump(mode="json")
                )
                mappings = await self.ctid_mapper.map_description(
                    cve, normalized, candidates, source_url=source_url
                )
            except (CTIDMappingError, GraphUnavailable):
                logger.exception("CTID-only mapping failed", extra={"cve_id": cve.cve_id})
                raise
        return CVEAnalysis(
            cve=cve,
            exploit_steps=[],
            attack_mappings=[],
            attack_chain=[],
            cve_level_attack_mappings=mappings,
            subgraph=EvidenceSubgraph(),
            warnings=list(dict.fromkeys(warnings)),
        )
