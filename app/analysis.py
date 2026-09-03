import asyncio
import hashlib
import logging

import httpx

from app.advisory.client import (
    AdvisoryClient,
    FetchedAdvisory,
    SelectedReference,
    UnsupportedAdvisoryContent,
    select_references,
)
from app.config import Settings
from app.enrichment.attack_mapper import (
    MAPPING_PROMPT_VERSION,
    FHGenieAttackMapper,
    MappingResponseError,
)
from app.enrichment.fh_genie import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    DescriptionEvidence,
    ExtractionResponseError,
    FHGenieEvidenceAgent,
    normalized_description_evidence,
)
from app.enrichment.validation_agent import (
    VALIDATION_PROMPT_VERSION,
    FHGenieValidationAgent,
    ValidationResponseError,
    unvalidated_chain,
)
from app.graph.repository import GraphRepository
from app.ingestion.service import CVEIngestionService, normalize_cve_id
from app.models import (
    AdvisoryResult,
    AttackMapping,
    CVEAnalysis,
    DescriptionEvidenceResult,
    ExtractionStatus,
)

logger = logging.getLogger(__name__)


class CVEAnalysisService:
    def __init__(
        self,
        settings: Settings,
        graph: GraphRepository,
        client: httpx.AsyncClient,
        agent: FHGenieEvidenceAgent | None = None,
        mapper: FHGenieAttackMapper | None = None,
        validator: FHGenieValidationAgent | None = None,
    ) -> None:
        self.settings = settings
        self.graph = graph
        self.client = client
        self.agent = agent
        self.mapper = mapper
        self.validator = validator

    async def analyze(self, cve_id: str) -> CVEAnalysis:
        normalized_id = normalize_cve_id(cve_id)
        await self.graph.verify_taxonomy()
        cve = await self.graph.cached_cve(normalized_id, self.settings.cache_ttl_seconds)
        if cve is None:
            cve = await CVEIngestionService(self.settings, self.client).analyze(normalized_id)
        selected = select_references(cve.references, self.settings.advisory_allowed_domains)
        advisory_client = AdvisoryClient(
            self.client, max_bytes=self.settings.advisory_max_bytes
        )
        fetched: list[FetchedAdvisory] = []
        results: list[AdvisoryResult] = []
        warnings = list(cve.warnings)
        description = normalized_description_evidence(cve)
        description_result = (
            DescriptionEvidenceResult(
                source_name=description.source_name,
                source_url=description.source_url,
                extraction_status=ExtractionStatus.COMPLETED,
            )
            if description
            else None
        )

        async def fetch_one(
            item: SelectedReference,
        ) -> tuple[SelectedReference, FetchedAdvisory | Exception]:
            try:
                return item, await advisory_client.fetch(item)
            except Exception as exc:
                return item, exc

        outcomes = await asyncio.gather(*(fetch_one(item) for item in selected))
        for selected_item, outcome in outcomes:
            if isinstance(outcome, FetchedAdvisory):
                fetched.append(outcome)
                results.append(
                    AdvisoryResult(
                        url=outcome.selected.reference.url,
                        reference_tags=outcome.selected.reference.tags,
                        selection_reason=outcome.selected.reason,
                        retrieved_at=outcome.retrieved_at,
                        checksum=outcome.checksum,
                        extraction_status=ExtractionStatus.COMPLETED,
                    )
                )
            else:
                status = (
                    ExtractionStatus.UNSUPPORTED_CONTENT
                    if isinstance(outcome, UnsupportedAdvisoryContent)
                    else ExtractionStatus.FETCH_FAILED
                )
                results.append(
                    AdvisoryResult(
                        url=selected_item.reference.url,
                        reference_tags=selected_item.reference.tags,
                        selection_reason=selected_item.reason,
                        extraction_status=status,
                    )
                )
                warnings.append(f"Advisory unavailable: {selected_item.reference.url}")

        model = self.agent.model if self.agent else "unconfigured"
        cache_key = self._cache_key(fetched, model, description)
        has_evidence = bool(fetched or description)
        steps = await self.graph.cached_steps(cve.cve_id, cache_key) if has_evidence else None
        if steps is None:
            steps = []
            if not has_evidence:
                warnings.append("No trusted description or advisory evidence was available")
            elif self.agent is None:
                warnings.append("FH Genie is not configured; exploit-step extraction was skipped")
                if description_result:
                    description_result.extraction_status = ExtractionStatus.EXTRACTION_FAILED
                for result in results:
                    if result.extraction_status == ExtractionStatus.COMPLETED:
                        result.extraction_status = ExtractionStatus.EXTRACTION_FAILED
            else:
                try:
                    steps = await self.agent.extract(cve.cve_id, fetched, description)
                except ExtractionResponseError as exc:
                    warnings.append(str(exc))
                    if description_result:
                        description_result.extraction_status = ExtractionStatus.EXTRACTION_FAILED
                    for result in results:
                        if result.extraction_status == ExtractionStatus.COMPLETED:
                            result.extraction_status = ExtractionStatus.EXTRACTION_FAILED

        await self.graph.replace_analysis(
            cve,
            fetched,
            steps,
            cache_key=cache_key,
            model=model,
            prompt_version=PROMPT_VERSION,
        )
        mappings: list[AttackMapping] = []
        mapping_completed = False
        if steps and self.mapper is None:
            warnings.append("FH Genie ATT&CK mapper is not configured")
        elif steps and self.mapper is not None:
            platforms = sorted(
                {
                    platform
                    for product in cve.affected_products
                    for platform in product.platforms
                }
            )
            candidate_lists = await asyncio.gather(
                *(
                    self.graph.attack_candidates(
                        step,
                        platforms,
                        cve_id=cve.cve_id,
                        cwe_ids=cve.cwe_ids,
                        capec_ids=cve.capec_ids,
                        cve_description=cve.description,
                    )
                    for step in steps
                )
            )
            candidates = {
                step.step: candidate_list
                for step, candidate_list in zip(steps, candidate_lists, strict=True)
            }
            try:
                mappings = await self.mapper.map_steps(cve, steps, candidates)
                mapping_completed = True
            except MappingResponseError as exc:
                warnings.append(str(exc))
            if mapping_completed:
                await self.graph.replace_attack_mappings(
                    cve.cve_id,
                    mappings,
                    model=self.mapper.model,
                    prompt_version=MAPPING_PROMPT_VERSION,
                )
        attack_chain = []
        if steps and not mappings:
            attack_chain = unvalidated_chain(
                steps, "No ATT&CK mapping was available for independent validation."
            )
        elif mappings and self.validator is None:
            warnings.append("FH Genie ATT&CK validator is not configured")
            attack_chain = unvalidated_chain(
                steps, "The proposed mapping was not promoted because validation is unavailable."
            )
        elif mappings and self.validator is not None:
            official = await self.graph.official_attack_context(
                [
                    item.mitre_technique_id
                    for item in mappings
                    if item.mitre_technique_id is not None
                ]
            )
            graph_facts = await self.graph.validation_facts(
                cve.cve_id,
                mappings,
                sorted(
                    {
                        platform
                        for product in cve.affected_products
                        for platform in product.platforms
                    }
                ),
            )
            try:
                attack_chain = await self.validator.validate(
                    cve, steps, mappings, official, graph_facts
                )
            except ValidationResponseError as exc:
                logger.error(
                    "ATT&CK validation pipeline failed",
                    extra={
                        "cve_id": cve.cve_id,
                        "validation_stage": "final_validation",
                        "exception_type": type(exc).__name__,
                        "exception_message": str(exc),
                        "failure_reason": exc.failure_reason,
                        "step": exc.context.get("step"),
                        "technique_id": exc.context.get("technique_id"),
                    },
                )
                warnings.append(str(exc))
                attack_chain = unvalidated_chain(
                    steps,
                    "The proposed mapping was not promoted because grounded validation failed.",
                )
        if attack_chain:
            await self.graph.replace_validated_attack_chain(
                cve.cve_id,
                attack_chain,
                mapping_model=self.mapper.model if self.mapper else "unconfigured",
                mapping_prompt_version=MAPPING_PROMPT_VERSION,
                validation_model=(
                    self.validator.model if self.validator else "unconfigured"
                ),
                validation_prompt_version=VALIDATION_PROMPT_VERSION,
            )
        subgraph = await self.graph.subgraph(cve.cve_id)
        return CVEAnalysis(
            cve=cve,
            description_evidence=description_result,
            advisories=sorted(results, key=lambda item: str(item.url)),
            exploit_steps=steps,
            attack_mappings=mappings,
            attack_chain=attack_chain,
            subgraph=subgraph,
            warnings=list(dict.fromkeys(warnings)),
        )

    @staticmethod
    def _cache_key(
        advisories: list[FetchedAdvisory],
        model: str,
        description: DescriptionEvidence | None = None,
    ) -> str:
        material = "\0".join(
            [
                model,
                PROMPT_VERSION,
                hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
                *(
                    [description.source_name, description.source_url, description.text]
                    if description
                    else []
                ),
                *sorted(item.checksum for item in advisories),
            ]
        )
        return hashlib.sha256(material.encode()).hexdigest()
