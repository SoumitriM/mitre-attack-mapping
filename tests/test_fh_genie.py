from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.advisory.client import FetchedAdvisory, SelectedReference
from app.config import Settings
from app.enrichment.fh_genie import ExtractionResponseError, FHGenieEvidenceAgent
from app.models import Reference, SelectionReason


def advisory() -> FetchedAdvisory:
    from datetime import UTC, datetime

    selected = SelectedReference(
        Reference(url="https://research.example/advisory", source="test", tags=["exploit"]),
        SelectionReason.PRIORITY_TAG,
    )
    return FetchedAdvisory(
        selected,
        "The attacker registers the abandoned domain. The client downloads payload.exe.",
        datetime.now(UTC),
        "sha256:test",
    )


def settings() -> Settings:
    return Settings(
        _env_file=None,
        fh_genie_key="secret",
        fh_genie_base_url="https://fh.example/v1",
        fh_genie_model="model",
    )


def response(content: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


@pytest.mark.asyncio
async def test_extracts_sequential_grounded_steps() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response(
        '{"steps":[{"step":1,"action":"Register domain","prerequisites":[], '
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}]}'
    ))

    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2026-22306", [advisory()])

    assert steps[0].action == "Register domain"


def test_grounding_accepts_equivalent_trailing_slash_url() -> None:
    from app.models import ExploitStepEnvelope

    result = ExploitStepEnvelope.model_validate({
        "steps": [{
            "step": 1,
            "action": "Register domain",
            "prerequisites": [],
            "outcome": "Domain controlled",
            "evidence": [{
                "source_url": "https://research.example/advisory/",
                "supporting_text": "The attacker registers the abandoned domain.",
            }],
        }]
    })

    assert FHGenieEvidenceAgent._is_grounded(result, [advisory()])


@pytest.mark.asyncio
async def test_retries_and_rejects_invented_evidence_without_leaking_content() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response(
        '{"steps":[{"step":1,"action":"Invented","prerequisites":[], '
        '"outcome":"Invented","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":"private invented text"}]}]}'
    ))

    with pytest.raises(ExtractionResponseError, match="unsupported evidence") as raised:
        await FHGenieEvidenceAgent(settings(), api).extract("CVE-2026-22306", [advisory()])

    assert "private invented text" not in str(raised.value)
    assert api.chat.completions.create.await_count == 2
    retry_messages = api.chat.completions.create.await_args.kwargs["messages"]
    assert "steps [1]" in retry_messages[-1]["content"]
