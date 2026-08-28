import asyncio
import hashlib

import httpx

from app.advisory.client import (
    AdvisoryClient,
    FetchedAdvisory,
    SelectedReference,
    UnsupportedAdvisoryContent,
    select_references,
)
from app.config import Settings
from app.enrichment.fh_genie import (
    PROMPT_VERSION,
    ExtractionResponseError,
    FHGenieEvidenceAgent,
)
from app.graph.repository import GraphRepository
from app.ingestion.service import CVEIngestionService
from app.models import AdvisoryResult, CVEAnalysis, ExtractionStatus


class CVEAnalysisService:
    def __init__(
        self,
        settings: Settings,
        graph: GraphRepository,
        client: httpx.AsyncClient,
        agent: FHGenieEvidenceAgent | None = None,
    ) -> None:
        self.settings = settings
        self.graph = graph
        self.client = client
        self.agent = agent

    async def analyze(self, cve_id: str) -> CVEAnalysis:
        await self.graph.verify_taxonomy()
        cve = await CVEIngestionService(self.settings, self.client).analyze(cve_id)
        selected = select_references(cve.references, self.settings.advisory_allowed_domains)
        advisory_client = AdvisoryClient(
            self.client, max_bytes=self.settings.advisory_max_bytes
        )
        fetched: list[FetchedAdvisory] = []
        results: list[AdvisoryResult] = []
        warnings = list(cve.warnings)

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
        cache_key = self._cache_key(fetched, model)
        steps = await self.graph.cached_steps(cve.cve_id, cache_key) if fetched else None
        if steps is None:
            steps = []
            if not fetched:
                warnings.append("No trusted advisory evidence was available for extraction")
            elif self.agent is None:
                warnings.append("FH Genie is not configured; exploit-step extraction was skipped")
                for result in results:
                    if result.extraction_status == ExtractionStatus.COMPLETED:
                        result.extraction_status = ExtractionStatus.EXTRACTION_FAILED
            else:
                try:
                    steps = await self.agent.extract(cve.cve_id, fetched)
                except ExtractionResponseError as exc:
                    warnings.append(str(exc))
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
        subgraph = await self.graph.subgraph(cve.cve_id)
        return CVEAnalysis(
            cve=cve,
            advisories=sorted(results, key=lambda item: str(item.url)),
            exploit_steps=steps,
            subgraph=subgraph,
            warnings=list(dict.fromkeys(warnings)),
        )

    @staticmethod
    def _cache_key(advisories: list[FetchedAdvisory], model: str) -> str:
        material = "\0".join(
            [model, PROMPT_VERSION, *sorted(item.checksum for item in advisories)]
        )
        return hashlib.sha256(material.encode()).hexdigest()
