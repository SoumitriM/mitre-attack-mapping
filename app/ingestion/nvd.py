from typing import Any

from app.ingestion.base import JSONSourceClient, SourceError


class NVDClient(JSONSourceClient):
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, *args: Any, api_key: str | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.api_key = api_key

    async def fetch(self, cve_id: str) -> dict[str, Any]:
        headers = {"apiKey": self.api_key} if self.api_key else None
        payload = await self._get_json(self.BASE_URL, params={"cveId": cve_id}, headers=headers)
        if not payload.get("vulnerabilities"):
            raise SourceError(f"NVD has no record for {cve_id}")
        return payload
