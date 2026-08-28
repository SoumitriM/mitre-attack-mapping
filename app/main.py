from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(
    title="MITRE Attack Chain",
    version="0.1.0",
    description="Phase 1: authoritative CVE ingestion and normalized output.",
)
app.include_router(router)


@app.get("/healthz", tags=["operations"])
async def health() -> dict[str, str]:
    return {"status": "ok"}
