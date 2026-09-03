from typing import cast

import httpx
from fastapi import APIRouter, HTTPException
from neo4j import AsyncGraphDatabase
from pydantic import BaseModel, Field

from app.analysis import CVEAnalysisService
from app.config import get_settings
from app.enrichment.attack_mapper import FHGenieAttackMapper
from app.enrichment.candidate_retrieval import EmbeddingClient
from app.enrichment.fh_genie import FHGenieEvidenceAgent
from app.enrichment.validation_agent import FHGenieValidationAgent
from app.graph.repository import GraphRepository, GraphUnavailable
from app.ingestion.service import CVENotAvailable, InvalidCVEID, normalize_cve_id
from app.models import AttackChainGraph, CVEAnalysis

router = APIRouter(prefix="/api", tags=["cve"])


class AnalyzeRequest(BaseModel):
    cve_id: str = Field(examples=["CVE-2026-22306"])


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


@router.post("/cve-analysis", response_model=CVEAnalysis)
async def analyze(request: AnalyzeRequest) -> CVEAnalysis:
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
        except ValueError:
            agent = None
            mapper = None
            validator = None
        graph = GraphRepository(
            driver,
            cast(EmbeddingClient, agent.client) if agent else None,
            settings.fh_genie_embedding_model if agent else None,
            agent.client if agent else None,
            settings.fh_genie_model if agent else None,
        )
        await graph.initialize()
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            return await CVEAnalysisService(
                settings, graph, client, agent, mapper, validator
            ).analyze(request.cve_id)
    except InvalidCVEID as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CVENotAvailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except GraphUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        await driver.close()
