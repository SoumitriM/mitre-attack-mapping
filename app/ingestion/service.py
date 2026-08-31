import asyncio
import re
from collections.abc import Awaitable
from typing import Any

import httpx

from app.config import Settings
from app.ingestion.base import SourceError
from app.ingestion.cvelist import CVEListV5Client
from app.ingestion.normalize import normalize
from app.ingestion.nvd import NVDClient
from app.models import CVERecord

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class InvalidCVEID(ValueError):
    pass


class CVENotAvailable(RuntimeError):
    pass


def normalize_cve_id(cve_id: str) -> str:
    normalized_id = cve_id.strip().upper()
    if not CVE_PATTERN.fullmatch(normalized_id):
        raise InvalidCVEID("Expected a CVE ID such as CVE-2024-12345")
    return normalized_id


async def _capture(task: Awaitable[dict[str, Any]]) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return await task, None
    except SourceError as exc:
        return None, str(exc)


class CVEIngestionService:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client

    async def analyze(self, cve_id: str) -> CVERecord:
        normalized_id = normalize_cve_id(cve_id)

        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.settings.http_timeout_seconds)
        try:
            cve_client = CVEListV5Client(client, self.settings.http_max_retries)
            nvd_client = NVDClient(
                client, self.settings.http_max_retries, api_key=self.settings.nvd_api_key
            )
            (nvd_data, nvd_warning), (cve_data, cve_warning) = await asyncio.gather(
                _capture(nvd_client.fetch(normalized_id)), _capture(cve_client.fetch(normalized_id))
            )
            if cve_data is None and nvd_data is None:
                raise CVENotAvailable(f"No authoritative source returned {normalized_id}")
            record = normalize(normalized_id, cve_data, nvd_data)
            record.warnings = [warning for warning in (cve_warning, nvd_warning) if warning]
            return record
        finally:
            if owns_client:
                await client.aclose()
