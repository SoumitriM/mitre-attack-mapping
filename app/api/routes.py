from typing import Literal, cast

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from neo4j import AsyncGraphDatabase
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

from app.analysis import CVEAnalysisService
from app.api.jobs import AnalysisJobs, DescriptionSource, JobSnapshot
from app.api.response_names import resolve_attack_names
from app.config import get_settings
from app.enrichment.attack_mapper import FHGenieAttackMapper
from app.enrichment.candidate_retrieval import EmbeddingClient, RerankClient
from app.enrichment.ctid_mapper import CTIDMappingError, FHGenieCTIDCVEMapper
from app.enrichment.fh_genie import AsyncCompatibleClient, FHGenieEvidenceAgent
from app.graph.repository import GraphRepository, GraphUnavailable
from app.ingestion.service import CVENotAvailable, InvalidCVEID, normalize_cve_id
from app.models import (
    CVEAnalysis,
    CVELevelAttackMapping,
    MappingProcessingStatus,
    ValidationStatus,
)

router = APIRouter(prefix="/api", tags=["cve"])


class AnalyzeRequest(BaseModel):
    cve_ids: list[str] = Field(
        min_length=1,
        examples=[["CVE-2026-22306", "CVE-2025-0282"]],
    )
    description_source: DescriptionSource = "auto"


class CompactAttackStep(BaseModel):
    step: int
    action: str
    technique_id: str | None
    tactic_id: str | None
    technique_name: str | None = None
    tactic_name: str | None = None
    confidence: float
    mapped: bool


class CompactCTIDTechnique(BaseModel):
    id: str
    action: str
    technique_id: str | None
    tactic_id: str | None
    technique_name: str | None = None
    tactic_name: str | None = None
    status: MappingProcessingStatus


class CompactCTIDLinkedBehavior(CompactCTIDTechnique):
    enabled_by: list[str]


class CompactCTIDMap(BaseModel):
    exploitation_techniques: list[CompactCTIDTechnique]
    primary_impacts: list[CompactCTIDLinkedBehavior]
    secondary_impacts: list[CompactCTIDLinkedBehavior]


class CompactCVEAnalysis(BaseModel):
    cve_id: str
    attack_chain: list[CompactAttackStep]
    ctid_map: CompactCTIDMap


def compact_ctid_map(result: CVEAnalysis) -> CompactCTIDMap:
    def ctid_item(item: CVELevelAttackMapping, *, linked: bool) -> CompactCTIDTechnique:
        values = {
            "id": item.id,
            "action": item.action,
            "technique_id": item.mitre_technique_id,
            "tactic_id": item.mitre_tactic_id,
            "technique_name": item.technique_name,
            "tactic_name": item.tactic_name,
            "status": item.processing_status,
        }
        if linked:
            return CompactCTIDLinkedBehavior(**values, enabled_by=item.enabled_by)
        return CompactCTIDTechnique(**values)

    mappings = result.cve_level_attack_mappings
    return CompactCTIDMap(
        exploitation_techniques=[
            ctid_item(item, linked=False) for item in mappings.exploitation_techniques
        ],
        primary_impacts=[ctid_item(item, linked=True) for item in mappings.primary_impacts],
        secondary_impacts=[ctid_item(item, linked=True) for item in mappings.secondary_impacts],
    )


def compact_analysis_view(result: CVEAnalysis) -> CompactCVEAnalysis:
    return CompactCVEAnalysis(
        cve_id=result.cve.cve_id,
        attack_chain=[
            CompactAttackStep(
                step=item.step,
                action=item.action,
                technique_id=item.proposed_technique_id,
                tactic_id=item.mitre_tactic_id,
                technique_name=item.technique_name,
                tactic_name=item.tactic_name,
                confidence=item.validation.validator_confidence,
                mapped=item.validation.status
                in {ValidationStatus.MAPPED, ValidationStatus.VALIDATED},
            )
            for item in result.attack_chain
        ],
        ctid_map=compact_ctid_map(result),
    )


class AnalysisJobError(BaseModel):
    code: int
    message: str


class PendingAnalysisJob(BaseModel):
    job_id: str
    status: Literal["pending"] = "pending"
    poll_url: str


class CompletedAnalysisJob(BaseModel):
    job_id: str
    status: Literal["completed"] = "completed"
    poll_url: str
    results: list[CVEAnalysis | CompactCVEAnalysis]


class FailedAnalysisJob(BaseModel):
    job_id: str
    status: Literal["failed"] = "failed"
    poll_url: str
    error: AnalysisJobError


AnalysisJobResponse = PendingAnalysisJob | CompletedAnalysisJob | FailedAnalysisJob


def job_response(snapshot: JobSnapshot) -> AnalysisJobResponse:
    poll_url = f"/api/cve-analysis/{snapshot.job_id}"
    if snapshot.status == "completed":
        return CompletedAnalysisJob.model_validate(
            {"job_id": snapshot.job_id, "poll_url": poll_url, "results": snapshot.results}
        )
    if snapshot.status == "failed":
        return FailedAnalysisJob(
            job_id=snapshot.job_id, poll_url=poll_url,
            error=AnalysisJobError(
                code=snapshot.error_code or 500,
                message=snapshot.error_message or "Analysis failed",
            ),
        )
    return PendingAnalysisJob(job_id=snapshot.job_id, poll_url=poll_url)


@router.post(
    "/cve-analysis", status_code=202,
    response_model=AnalysisJobResponse,
)
async def analyze(
    request: AnalyzeRequest, http_request: Request, response: Response, compact: bool = True
) -> AnalysisJobResponse:
    settings = get_settings()
    if settings.neo4j_password is None:
        raise HTTPException(status_code=503, detail="Neo4j is not configured")
    try:
        cve_ids = [normalize_cve_id(cve_id) for cve_id in request.cve_ids]
    except InvalidCVEID as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    jobs = cast(AnalysisJobs, http_request.app.state.analysis_jobs)
    result = job_response(jobs.submit(cve_ids, compact, request.description_source))
    response.headers["Location"] = result.poll_url
    response.headers["Retry-After"] = "3"
    response.headers["Cache-Control"] = "no-store"
    return result


@router.get(
    "/cve-analysis/{job_id}",
    response_model=AnalysisJobResponse,
)
async def poll_analysis(
    job_id: str, http_request: Request, response: Response
) -> AnalysisJobResponse:
    jobs = cast(AnalysisJobs, http_request.app.state.analysis_jobs)
    result = job_response(jobs.get(job_id))
    response.headers["Cache-Control"] = "no-store"
    if result.status == "pending":
        response.headers["Retry-After"] = "3"
    return result


async def run_analysis_batch(
    cve_ids: list[str], compact: bool, description_source: DescriptionSource
) -> list[dict[str, object]]:
    settings = get_settings()
    if settings.neo4j_password is None:
        raise HTTPException(status_code=503, detail="Neo4j is not configured")
    owned_clients: list[AsyncOpenAI] = []
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password.get_secret_value()),
    )
    try:
        agent: FHGenieEvidenceAgent | None
        mapper: FHGenieAttackMapper | None
        ctid_mapper: FHGenieCTIDCVEMapper | None
        downstream_client: AsyncCompatibleClient | None
        try:
            agent = FHGenieEvidenceAgent(settings)
            downstream_client = agent.downstream_client
            owned_clients = [
                cast(AsyncOpenAI, agent.client), cast(AsyncOpenAI, downstream_client)
            ]
            mapper = FHGenieAttackMapper(settings, downstream_client)
            ctid_mapper = (
                FHGenieCTIDCVEMapper(mapper.model, downstream_client)
                if settings.enable_ctid_mapping
                else None
            )
        except ValueError:
            agent = None
            mapper = None
            ctid_mapper = None
            downstream_client = None
        graph = GraphRepository(
            driver,
            cast(EmbeddingClient, downstream_client) if downstream_client else None,
            settings.fh_genie_embedding_model if downstream_client else None,
            cast(RerankClient, downstream_client) if downstream_client else None,
            settings.downstream_model if downstream_client else None,
            settings.attack_embedding_cache_path,
        )
        await graph.initialize()
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            service = CVEAnalysisService(
                settings, graph, client, agent, mapper, ctid_mapper
            )
            results = [
                await service.analyze(cve_id, description_source=description_source)
                for cve_id in cve_ids
            ]
            await resolve_attack_names(results, graph)
            if compact:
                return [compact_analysis_view(result).model_dump(mode="json") for result in results]
            return [result.model_dump(mode="json") for result in results]
    except InvalidCVEID as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CVENotAvailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except CTIDMappingError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except GraphUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        try:
            await driver.close()
        finally:
            for inference_client in {id(item): item for item in owned_clients}.values():
                await inference_client.close()
