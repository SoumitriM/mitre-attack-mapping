from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.jobs import AnalysisJobs
from app.api.routes import router, run_analysis_batch
from app.config import get_settings


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    jobs = AnalysisJobs(
        run_analysis_batch,
        retention_seconds=settings.analysis_job_retention_seconds,
        capacity=settings.analysis_job_capacity,
        concurrency=settings.analysis_job_concurrency,
    )
    application.state.analysis_jobs = jobs
    try:
        yield
    finally:
        await jobs.close()


app = FastAPI(
    lifespan=lifespan,
    title="MITRE Attack Chain",
    version="0.1.0",
    description="Evidence-grounded CVE and exploit-step analysis.",
)
app.include_router(router)


@app.get("/healthz", tags=["operations"])
async def health() -> dict[str, str]:
    return {"status": "ok"}
