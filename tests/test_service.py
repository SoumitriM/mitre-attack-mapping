import httpx
import pytest
import respx

from app.config import Settings
from app.ingestion.cve import CVEOrgClient
from app.ingestion.nvd import NVDClient
from app.ingestion.service import CVEIngestionService, InvalidCVEID


@pytest.mark.asyncio
async def test_rejects_invalid_cve_id() -> None:
    with pytest.raises(InvalidCVEID):
        await CVEIngestionService(Settings()).analyze("not-a-cve")


@respx.mock
@pytest.mark.asyncio
async def test_analyze_tolerates_one_unavailable_source() -> None:
    cve_id = "CVE-2024-3094"
    respx.get(f"{CVEOrgClient.BASE_URL}/{cve_id}").mock(
        return_value=httpx.Response(
            200,
            json={
                "cveMetadata": {},
                "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Known issue"}]}},
            },
        )
    )
    respx.get(NVDClient.BASE_URL, params={"cveId": cve_id}).mock(
        return_value=httpx.Response(503)
    )
    settings = Settings(http_max_retries=0)
    async with httpx.AsyncClient() as client:
        record = await CVEIngestionService(settings, client).analyze(cve_id)

    assert record.description == "Known issue"
    assert len(record.warnings) == 1
