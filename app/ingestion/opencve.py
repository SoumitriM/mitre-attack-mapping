"""Fetch only the public OpenCVE description, without advisories or model calls."""

import httpx
from bs4 import BeautifulSoup

from app.enrichment.fh_genie import DescriptionEvidence
from app.ingestion.service import normalize_cve_id


async def fetch_opencve_description(
    cve_id: str, client: httpx.AsyncClient
) -> DescriptionEvidence:
    """Fetch once and fail explicitly when the expected description is unavailable."""
    normalized_id = normalize_cve_id(cve_id)
    url = f"https://app.opencve.io/cve/{normalized_id}"
    response = await client.get(url, follow_redirects=False)
    response.raise_for_status()
    if "text/html" not in response.headers.get("content-type", "").lower():
        raise ValueError("OpenCVE did not return an HTML CVE page")
    soup = BeautifulSoup(response.text, "html.parser")
    title = soup.find("title")
    if title is None or normalized_id not in title.get_text():
        raise ValueError("OpenCVE page does not identify the requested CVE")
    node = soup.select_one("#cve-description-text")
    if node is None:
        raise ValueError("OpenCVE description element was not found")
    description = node.get_text(" ", strip=True)
    if not description:
        raise ValueError("OpenCVE description is empty")
    return DescriptionEvidence("OpenCVE", url, description)
