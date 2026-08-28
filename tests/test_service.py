import json
from pathlib import Path

import httpx
import pytest
import respx

from app.config import Settings
from app.ingestion.nvd import NVDClient
from app.ingestion.service import CVEIngestionService, InvalidCVEID


@pytest.mark.asyncio
async def test_rejects_invalid_cve_id() -> None:
    with pytest.raises(InvalidCVEID):
        await CVEIngestionService(Settings()).analyze("not-a-cve")


@respx.mock
@pytest.mark.asyncio
async def test_analyze_falls_back_to_local_cvelist(tmp_path: Path) -> None:
    cve_id = "CVE-2024-3094"
    record_path = tmp_path / "cves" / "2024" / "3xxx" / f"{cve_id}.json"
    record_path.parent.mkdir(parents=True)
    record_path.write_text(json.dumps({
        "cveMetadata": {},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Known issue"}]}},
    }))
    respx.get(NVDClient.BASE_URL, params={"cveId": cve_id}).mock(
        return_value=httpx.Response(503)
    )
    settings = Settings(http_max_retries=0, cvelist_v5_root=tmp_path)
    async with httpx.AsyncClient() as client:
        record = await CVEIngestionService(settings, client).analyze(cve_id)

    assert record.description == "Known issue"
    assert len(record.warnings) == 1
