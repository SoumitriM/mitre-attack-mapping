from typing import Any

from app.ingestion.base import JSONSourceClient


class CVEListV5Client(JSONSourceClient):
    """Fetch one CVE JSON 5 record live from the official CVE List repository."""

    BASE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"

    async def fetch(self, cve_id: str) -> dict[str, Any]:
        _, year, sequence = cve_id.split("-")
        bucket = f"{sequence[:-3]}xxx" if len(sequence) > 3 else "0xxx"
        return await self._get_json(f"{self.BASE_URL}/{year}/{bucket}/{cve_id}.json")
