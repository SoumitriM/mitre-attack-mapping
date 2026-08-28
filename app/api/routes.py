import httpx
from fastapi import APIRouter, HTTPException
from neo4j import AsyncGraphDatabase
from pydantic import BaseModel, Field

from app.analysis import CVEAnalysisService
from app.config import get_settings
from app.enrichment.fh_genie import FHGenieEvidenceAgent
from app.graph.repository import GraphRepository, GraphUnavailable
from app.ingestion.service import CVENotAvailable, InvalidCVEID
from app.models import CVEAnalysis

router = APIRouter(prefix="/api", tags=["cve"])


class AnalyzeRequest(BaseModel):
    cve_id: str = Field(examples=["CVE-2026-22306"])


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
        graph = GraphRepository(driver)
        await graph.initialize()
        try:
            agent = FHGenieEvidenceAgent(settings)
        except ValueError:
            agent = None
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            return await CVEAnalysisService(settings, graph, client, agent).analyze(
                request.cve_id
            )
    except InvalidCVEID as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CVENotAvailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except GraphUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        await driver.close()
