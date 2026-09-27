from typing import cast

import httpx
from fastapi import APIRouter, HTTPException
from neo4j import AsyncGraphDatabase
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

from app.analysis import CVEAnalysisService
from app.config import get_settings
from app.enrichment.attack_mapper import FHGenieAttackMapper
from app.enrichment.candidate_retrieval import EmbeddingClient, RerankClient
from app.enrichment.ctid_mapper import CTIDMappingError, FHGenieCTIDCVEMapper
from app.enrichment.fh_genie import AsyncCompatibleClient, FHGenieEvidenceAgent
from app.enrichment.validation_agent import FHGenieValidationAgent
from app.graph.repository import GraphRepository, GraphUnavailable
from app.ingestion.service import CVENotAvailable, InvalidCVEID, normalize_cve_id
from app.models import (
    AttackChainGraph,
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


class CompactAttackStep(BaseModel):
    step: int
    action: str
    technique_id: str | None
    tactic_id: str | None
    confidence: float
    mapped: bool


class CompactCTIDTechnique(BaseModel):
    id: str
    action: str
    technique_id: str | None
    tactic_id: str | None
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


class CTIDOnlyAnalysis(BaseModel):
    ctid_map: CompactCTIDMap


def compact_ctid_map(result: CVEAnalysis) -> CompactCTIDMap:
    def ctid_item(item: CVELevelAttackMapping, *, linked: bool) -> CompactCTIDTechnique:
        values = {
            "id": item.id,
            "action": item.action,
            "technique_id": item.mitre_technique_id,
            "tactic_id": item.mitre_tactic_id,
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
                confidence=item.validation.validator_confidence,
                mapped=item.validation.status
                in {ValidationStatus.MAPPED, ValidationStatus.VALIDATED},
            )
            for item in result.attack_chain
        ],
    )


def ctid_only_view(result: CVEAnalysis) -> CTIDOnlyAnalysis:
    return CTIDOnlyAnalysis(ctid_map=compact_ctid_map(result))


@router.get("/cve-analysis/{cve_id}/graph", response_model=AttackChainGraph)
async def attack_chain_graph(cve_id: str) -> AttackChainGraph:
    settings = get_settings()
    if settings.neo4j_password is None:
        raise HTTPException(status_code=503, detail="Neo4j is not configured")
    try:
        normalized_id = normalize_cve_id(cve_id)
    except InvalidCVEID as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password.get_secret_value()),
    )
    try:
        graph = await GraphRepository(driver).validated_attack_chain_graph(normalized_id)
        if graph is None:
            raise HTTPException(status_code=404, detail="CVE analysis was not found")
        return graph
    except GraphUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        await driver.close()


@router.post(
    "/cve-analysis",
    response_model=list[CVEAnalysis | CompactCVEAnalysis | CTIDOnlyAnalysis],
)
async def analyze(
    request: AnalyzeRequest, compact: bool = True
) -> list[CVEAnalysis | CompactCVEAnalysis | CTIDOnlyAnalysis]:
    settings = get_settings()
    if settings.neo4j_password is None:
        raise HTTPException(status_code=503, detail="Neo4j is not configured")
    try:
        cve_ids = [normalize_cve_id(cve_id) for cve_id in request.cve_ids]
    except InvalidCVEID as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
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
            if settings.ctid_only_mode:
                if not (
                    settings.fh_genie_key and settings.fh_genie_base_url and settings.fh_genie_model
                ):
                    raise ValueError("FH Genie is required for CTID-only mode")
                downstream_client = cast(
                    AsyncCompatibleClient,
                    AsyncOpenAI(
                        api_key=settings.fh_genie_key.get_secret_value(),
                        base_url=settings.fh_genie_base_url,
                    ),
                )
                agent = None
                mapper = None
                validator = None
                ctid_mapper = FHGenieCTIDCVEMapper(settings.fh_genie_model, downstream_client)
            else:
                agent = FHGenieEvidenceAgent(settings)
                downstream_client = agent.downstream_client
                mapper = FHGenieAttackMapper(settings, downstream_client)
                validator = FHGenieValidationAgent(settings, downstream_client)
                ctid_mapper = (
                    FHGenieCTIDCVEMapper(mapper.model, downstream_client)
                    if settings.enable_ctid_mapping
                    else None
                )
        except ValueError:
            agent = None
            mapper = None
            validator = None
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
                settings, graph, client, agent, mapper, validator, ctid_mapper
            )
            results = [await service.analyze(cve_id) for cve_id in cve_ids]
            if settings.ctid_only_mode:
                return [ctid_only_view(result) for result in results]
            if compact:
                return [compact_analysis_view(result) for result in results]
            return [
                cast(CVEAnalysis | CompactCVEAnalysis | CTIDOnlyAnalysis, result)
                for result in results
            ]
    except InvalidCVEID as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CVENotAvailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except CTIDMappingError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except GraphUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        await driver.close()
