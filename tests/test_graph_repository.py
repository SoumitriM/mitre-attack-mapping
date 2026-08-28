from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.graph.repository import GraphRepository
from app.models import CVERecord, SourceAttribution


@pytest.mark.asyncio
async def test_graph_upsert_uses_cve_id_parameter() -> None:
    result = MagicMock()
    result.consume = AsyncMock()
    session = MagicMock()
    session.run = AsyncMock(return_value=result)
    context = AsyncMock()
    context.__aenter__.return_value = session
    driver = MagicMock()
    driver.session.return_value = context
    record = CVERecord(
        cve_id="CVE-2026-22306",
        sources=[
            SourceAttribution(
                name="NVD",
                url="https://nvd.nist.gov/vuln/detail/CVE-2026-22306",
                retrieved_at=datetime.now(UTC),
            )
        ],
    )

    await GraphRepository(driver).replace_analysis(
        record,
        [],
        [],
        cache_key="cache",
        model="model",
        prompt_version="v1",
    )

    query = session.run.await_args.args[0]
    parameters = session.run.await_args.kwargs
    assert "MERGE (cve:CVE {id: $cve.cve_id})" in query
    assert parameters["cve"]["cve_id"] == "CVE-2026-22306"
