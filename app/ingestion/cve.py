from typing import Any

from app.ingestion.base import JSONSourceClient


class CVEOrgClient(JSONSourceClient):
    BASE_URL = "https://cveawg.mitre.org/api/cve"

    async def fetch(self, cve_id: str) -> dict[str, Any]:
        return await self._get_json(f"{self.BASE_URL}/{cve_id}")
