from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.analysis import CVEAnalysisService
from app.config import Settings
from app.ingestion.opencve import fetch_opencve_description
from app.models import CVERecord


@pytest.mark.asyncio
async def test_description_excludes_other_page_sections():
    html = '''<title>CVE-2024-3400 - OpenCVE</title>
    <div id="cve-description-text">Inject commands.<br>Execute as root.</div>
    <div>Remediation: upgrade. History: unrelated exploit.</div>'''
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, text=html, headers={"content-type": "text/html"})
    )) as client:
        result = await fetch_opencve_description("cve-2024-3400", client)
    assert result.text == "Inject commands. Execute as root."
    assert result.source_url == "https://app.opencve.io/cve/CVE-2024-3400"


@pytest.mark.asyncio
@pytest.mark.parametrize("html", [
    '<title>CVE-2024-3400</title><div>Login required</div>',
    '<title>CVE-2024-3400</title><div id="cve-description-text"> </div>',
    '<title>CVE-2024-0012</title><div id="cve-description-text">Wrong CVE</div>',
])
async def test_invalid_page_fails_without_fallback(html):
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, text=html, headers={"content-type": "text/html"})
    )) as client:
        with pytest.raises(ValueError):
            await fetch_opencve_description("CVE-2024-3400", client)


@pytest.mark.asyncio
async def test_opencve_analysis_skips_advisories_and_compression(monkeypatch):
    from app.enrichment.fh_genie import FHGenieEvidenceAgent

    cve = CVERecord(cve_id="CVE-2024-3400", description="Original authoritative description")
    monkeypatch.setattr("app.analysis.CVEIngestionService.analyze", AsyncMock(return_value=cve))
    advisory = MagicMock(side_effect=AssertionError("Advisory fetch must not run"))
    monkeypatch.setattr("app.analysis.AdvisoryClient", advisory)
    graph = MagicMock()
    graph.verify_taxonomy = AsyncMock()
    llm = MagicMock()
    llm.chat.completions.create = AsyncMock(return_value=MagicMock(
        choices=[MagicMock(message=MagicMock(content='{"exploit_steps":[]}'))]
    ))
    agent = FHGenieEvidenceAgent(Settings(inference_provider="fh_genie"), client=llm)
    agent._compress_advisories = AsyncMock(side_effect=AssertionError("No compression"))
    html = '<title>CVE-2024-3400</title><div id="cve-description-text">Inject commands.</div>'
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, text=html, headers={"content-type": "text/html"})
    )) as client:
        service = CVEAnalysisService(Settings(ctid_only_mode=False), graph, client, agent)
        result = await service.analyze_opencve(cve.cve_id)
    assert result.advisories == []
    assert result.description_evidence.source_name == "OpenCVE"
    assert result.cve.description == "Inject commands."
    assert cve.description == "Original authoritative description"
    assert result.cve.field_provenance["description"] == ["OpenCVE"]
    agent._compress_advisories.assert_not_awaited()
    payload = llm.chat.completions.create.call_args.kwargs['messages'][1]['content']
    assert 'Inject commands.' in payload
