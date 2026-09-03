from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app.api.routes import router

app = FastAPI(
    title="MITRE Attack Chain",
    version="0.1.0",
    description="Evidence-grounded CVE and exploit-step analysis.",
)
app.include_router(router)


@app.get("/visualization", include_in_schema=False)
async def visualization() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/healthz", tags=["operations"])
async def health() -> dict[str, str]:
    return {"status": "ok"}
