from typing import cast

import httpx
from fastapi import APIRouter, HTTPException
from neo4j import AsyncGraphDatabase
from pydantic import BaseModel, Field

from app.analysis import CVEAnalysisService
from app.config import get_settings
from app.enrichment.attack_mapper import FHGenieAttackMapper
from app.enrichment.candidate_retrieval import EmbeddingClient
from app.enrichment.ctid_mapper import FHGenieCTIDCVEMapper
from app.enrichment.fh_genie import FHGenieEvidenceAgent
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
    cve_id: str = Field(examples=["CVE-2026-22306"])


class CompactAttackStep(BaseModel):
    step: int
    action: str
    technique_id: str | None
    tactic_id: str | None
    status: ValidationStatus


class CompactExploitStep(BaseModel):
    step: int
    action: str


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
    description: str | None
    exploit_steps: list[CompactExploitStep]
    attack_chain: list[CompactAttackStep]
    ctid_map: CompactCTIDMap


def compact_analysis_view(result: CVEAnalysis) -> CompactCVEAnalysis:
    def ctid_item(
        item: CVELevelAttackMapping, *, linked: bool
    ) -> CompactCTIDTechnique:
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
    return CompactCVEAnalysis(
        cve_id=result.cve.cve_id,
        description=result.cve.description,
        exploit_steps=[
            CompactExploitStep(step=item.step, action=item.action)
            for item in result.exploit_steps
        ],
        attack_chain=[
            CompactAttackStep(
                step=item.step,
                action=item.action,
                technique_id=item.proposed_technique_id,
                tactic_id=item.mitre_tactic_id,
                status=item.validation.status,
            )
            for item in result.attack_chain
        ],
        ctid_map=CompactCTIDMap(
            exploitation_techniques=[
                ctid_item(item, linked=False) for item in mappings.exploitation_techniques
            ],
            primary_impacts=[
                ctid_item(item, linked=True) for item in mappings.primary_impacts
            ],
            secondary_impacts=[
                ctid_item(item, linked=True) for item in mappings.secondary_impacts
            ],
        ),
    )


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


@router.post("/cve-analysis", response_model=CVEAnalysis | CompactCVEAnalysis)
async def analyze(
    request: AnalyzeRequest, compact: bool = True
) -> CVEAnalysis | CompactCVEAnalysis:
    settings = get_settings()
    if settings.neo4j_password is None:
        raise HTTPException(status_code=503, detail="Neo4j is not configured")
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password.get_secret_value()),
    )
    try:
        try:
            agent = FHGenieEvidenceAgent(settings)
            mapper = FHGenieAttackMapper(settings, agent.client)
            validator = FHGenieValidationAgent(settings, agent.client)
            ctid_mapper = FHGenieCTIDCVEMapper(mapper.model, agent.client)
        except ValueError:
            agent = None
            mapper = None
            validator = None
            ctid_mapper = None
        graph = GraphRepository(
            driver,
            cast(EmbeddingClient, agent.embedding_client) if agent else None,
            settings.fh_genie_embedding_model if agent else None,
            agent.client if agent else None,
            agent.model if agent else None,
        )
        await graph.initialize()
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            result = await CVEAnalysisService(
                settings, graph, client, agent, mapper, validator, ctid_mapper
            ).analyze(request.cve_id)
            return compact_analysis_view(result) if compact else result
    except InvalidCVEID as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CVENotAvailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except GraphUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        await driver.close()
