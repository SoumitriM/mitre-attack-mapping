from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.config import get_settings
from app.ingestion.service import CVEIngestionService, CVENotAvailable, InvalidCVEID
from app.models import CVERecord

router = APIRouter(prefix="/api", tags=["cve"])


class AnalyzeRequest(BaseModel):
    cve_id: str = Field(examples=["CVE-2024-3094"])


@router.post("/attack-path", response_model=CVERecord)
async def analyze(request: AnalyzeRequest) -> CVERecord:
    try:
        return await CVEIngestionService(get_settings()).analyze(request.cve_id)
    except InvalidCVEID as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CVENotAvailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
