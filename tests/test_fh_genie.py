import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import app.enrichment.fh_genie as fh_genie_module
from app.advisory.client import FetchedAdvisory, SelectedReference
from app.config import Settings
from app.enrichment.fh_genie import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    DescriptionEvidence,
    ExtractionResponseError,
    FHGenieEvidenceAgent,
)
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


def test_openrouter_can_be_selected_explicitly() -> None:
    api = MagicMock()
    configured = Settings(
        _env_file=None,
        inference_provider="openrouter",
        openrouter_key="openrouter-secret",
    )

    agent = FHGenieEvidenceAgent(configured, api)

    assert configured.inference_model == "anthropic/claude-opus-4.6"
    assert agent.model == "anthropic/claude-opus-4.6"
    assert agent.provider == "openrouter"
    assert agent.client is api
    assert agent.downstream_client is api


def test_fh_genie_is_the_default_even_with_an_openrouter_key() -> None:
    configured = Settings(
        _env_file=None,
        fh_genie_key="secret",
        fh_genie_base_url="https://fh.example/v1",
        fh_genie_model="MiniMaxAI/MiniMax-M2.5",
        openrouter_key="openrouter-secret",
    )

    assert configured.inference_model == "MiniMaxAI/MiniMax-M2.5"
    assert FHGenieEvidenceAgent(configured, MagicMock()).provider == "fh_genie"


@pytest.mark.asyncio
async def test_claude_extraction_is_one_call_and_hydrates_internal_evidence() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"exploit_steps":[{"step":1,"action":"Register the abandoned domain",'
            '"confidence":0.93}]}'
        )
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2026-22306", [advisory()])

    assert api.chat.completions.create.await_count == 1
    assert steps[0].confidence == 0.93
    assert steps[0].prerequisites == []
    assert steps[0].outcome == ""
    assert steps[0].evidence[0].supporting_text == ("The attacker registers the abandoned domain.")
    request = api.chat.completions.create.await_args.kwargs
    assert request["model"] == "model"
    assert request["response_format"] == {"type": "json_object"}


@pytest.mark.asyncio
async def test_openrouter_extraction_receives_minimax_summary_only() -> None:
    extraction_api = MagicMock()
    extraction_api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"exploit_steps":[{"step":1,"action":"Register the abandoned domain",'
            '"confidence":0.93}]}'
        )
    )
    minimax_api = MagicMock()
    minimax_api.chat.completions.create = AsyncMock(
        return_value=response(
            '{"passage":"The attacker registers the abandoned domain, causing the client to '
            'download a payload."}'
        )
    )
    configured = Settings(
        _env_file=None,
        inference_provider="openrouter",
        openrouter_key="openrouter-secret",
        fh_genie_key="fh-secret",
        fh_genie_base_url="https://fh.example/v1",
        fh_genie_model="MiniMaxAI/MiniMax-M2.5",
    )

    steps = await FHGenieEvidenceAgent(
        configured, extraction_api, downstream_client=minimax_api
    ).extract("CVE-2026-22306", [advisory()])

    assert minimax_api.chat.completions.create.await_count == 1
    assert extraction_api.chat.completions.create.await_count == 1
    compression_request = minimax_api.chat.completions.create.await_args.kwargs
    assert compression_request["model"] == "MiniMaxAI/MiniMax-M2.5"
    extraction_request = extraction_api.chat.completions.create.await_args.kwargs
    payload = json.loads(extraction_request["messages"][1]["content"])
    assert payload["advisories"] == [
        {
            "source_url": "https://research.example/advisory",
            "source_type": "minimax_advisory_summary",
            "source_name": "test",
            "text": (
                "The attacker registers the abandoned domain, causing the client to download a "
                "payload."
            ),
        }
    ]
    assert steps[0].evidence[0].supporting_text == "The attacker registers the abandoned domain."


def response(content: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


@pytest.fixture(autouse=True)
def isolate_fh_genie_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fh_genie_module, "RESPONSE_LOG_DIR", tmp_path)


def extraction_mock(extraction_content: str) -> AsyncMock:
    return AsyncMock(return_value=response(extraction_content))


def test_claude_prompt_requires_one_minimal_exploit_step_response() -> None:
    assert PROMPT_VERSION == "claude-exploit-steps-v5"
    assert "one response" in SYSTEM_PROMPT
    assert '"exploit_steps"' in SYSTEM_PROMPT
    assert '"confidence"' in SYSTEM_PROMPT
    assert "Do not add ATT&CK IDs" in SYSTEM_PROMPT
    assert "prerequisites" in SYSTEM_PROMPT
    assert "exactly one atomic technical attacker behavior" in SYSTEM_PROMPT
    assert 'joined by "or", "and", commas, sequential clauses' in SYSTEM_PROMPT
    assert "independently meaningful technical attacker" in SYSTEM_PROMPT
    assert "its direct outcome must remain in one step" in SYSTEM_PROMPT
    assert "retrieval-ready attacker behavior" in SYSTEM_PROMPT
    assert "Never generalize" in SYSTEM_PROMPT
    assert "do not emit a vulnerable system's" in SYSTEM_PROMPT
    assert "one causal vulnerability mechanism" in SYSTEM_PROMPT


@pytest.mark.asyncio
async def test_extracts_from_normalized_description_without_advisory() -> None:
    description = DescriptionEvidence(
        source_name="NVD",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-33557",
        text="An attacker can generate a JWT token and the broker will accept it.",
    )
    api = MagicMock()
    api.chat.completions.create = extraction_mock(
        '{"steps":[{"step":1,"action":"Forge JWT token","prerequisites":[],'
        '"outcome":"Broker accepts token","evidence":[{"source_url":'
        '"https://nvd.nist.gov/vuln/detail/CVE-2026-33557","supporting_text":'
        '"An attacker can generate a JWT token and the broker will accept it."}]}]}'
    )
    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2026-33557", [], description)
    payload = json.loads(api.chat.completions.create.await_args.kwargs["messages"][1]["content"])
    assert steps[0].action == "Forge JWT token"
    assert payload["description_evidence"]["source_name"] == "NVD"
    assert payload["advisories"] == []


@pytest.mark.asyncio
async def test_extracts_sequential_grounded_steps() -> None:
    api = MagicMock()
    api.chat.completions.create = extraction_mock(
        '{"steps":[{"step":1,"action":"Register domain","prerequisites":[], '
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}]}'
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2026-22306", [advisory()])

    assert steps[0].action == "Register domain"


@pytest.mark.asyncio
async def test_extraction_pipeline_skips_grounding() -> None:
    api = MagicMock()
    api.chat.completions.create = extraction_mock(
        '{"steps":[{"step":1,"action":"Invented","prerequisites":[], '
        '"outcome":"Invented","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":"private invented text"}]}]}',
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2026-22306", [advisory()])

    assert steps[0].evidence[0].supporting_text == "private invented text"
    assert api.chat.completions.create.await_count == 1


# ============================================================================
# New comprehensive tests for robustness and error handling
# ============================================================================


@pytest.mark.asyncio
async def test_handles_empty_response() -> None:
    """Test that empty responses are handled with specific error reason."""
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response(""))

    with pytest.raises(ExtractionResponseError) as raised:
        await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert raised.value.failure_reason == "empty_model_response"
    assert "empty" in str(raised.value).lower()


@pytest.mark.asyncio
async def test_handles_whitespace_only_response() -> None:
    """Test that whitespace-only responses are handled as empty."""
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response("   \n\t  "))

    with pytest.raises(ExtractionResponseError) as raised:
        await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert raised.value.failure_reason == "empty_model_response"


@pytest.mark.asyncio
async def test_handles_malformed_json() -> None:
    """Test that malformed JSON is caught with specific error reason."""
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response('{"steps": [invalid json]}'))

    with pytest.raises(ExtractionResponseError) as raised:
        await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert raised.value.failure_reason == "json_decode_failed"
    assert "json" in str(raised.value).lower()


@pytest.mark.asyncio
async def test_handles_json_with_markdown_fences() -> None:
    """Test that JSON wrapped in markdown code fences is extracted and parsed."""
    api = MagicMock()
    api.chat.completions.create = extraction_mock(
        "```json\n"
        '{"steps":[{"step":1,"action":"Register domain","prerequisites":[], '
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}]}\n'
        "```"
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert len(steps) == 1
    assert steps[0].action == "Register domain"


@pytest.mark.asyncio
async def test_handles_json_with_text_before_object() -> None:
    """Test that JSON preceded by explanatory text is extracted."""
    api = MagicMock()
    api.chat.completions.create = extraction_mock(
        "Here is the extracted exploit sequence:\n"
        '{"steps":[{"step":1,"action":"Register domain","prerequisites":[], '
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}]}'
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert len(steps) == 1
    assert steps[0].action == "Register domain"


@pytest.mark.asyncio
async def test_handles_json_with_markdown_fences_no_language() -> None:
    """Test markdown code fence extraction without language specifier."""
    api = MagicMock()
    api.chat.completions.create = extraction_mock(
        "```\n"
        '{"steps":[{"step":1,"action":"Register domain","prerequisites":[], '
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}]}\n'
        "```"
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert len(steps) == 1
    assert steps[0].action == "Register domain"


@pytest.mark.asyncio
async def test_handles_valid_json_with_wrong_schema() -> None:
    """Test that valid JSON with incorrect schema is rejected clearly."""
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response('{"wrong_field": "value"}'))

    with pytest.raises(ExtractionResponseError) as raised:
        await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert raised.value.failure_reason == "schema_validation_failed"
    assert "schema" in str(raised.value).lower() or "validation" in str(raised.value).lower()


@pytest.mark.asyncio
async def test_does_not_retry_a_malformed_envelope() -> None:
    bare_step = (
        '{"step":1,"action":"Register domain","prerequisites":[],'
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}'
    )
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response(bare_step))

    with pytest.raises(ExtractionResponseError):
        await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert api.chat.completions.create.await_count == 1


@pytest.mark.asyncio
async def test_handles_model_api_error() -> None:
    """Test handling of API/model call failures."""
    api = MagicMock()
    api.chat.completions.create = AsyncMock(side_effect=RuntimeError("API connection failed"))

    with pytest.raises(ExtractionResponseError) as raised:
        await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert raised.value.failure_reason == "model_call_failed"
    assert "API" in str(raised.value) or "error" in str(raised.value).lower()


@pytest.mark.asyncio
async def test_regression_multiple_advisories_extracted_successfully() -> None:
    """Regression test for CVE-2025-0282: multiple fetched advisories should not all fail.

    This test simulates the scenario where multiple advisories are fetched successfully
    but extraction fails for all due to format issues. With the improved parser, they
    should now succeed even with format variations.
    """
    from datetime import UTC, datetime

    # Create multiple advisories (simulating Google Threat Intelligence, GitHub, watchTowr, CISA)
    advisories = [
        FetchedAdvisory(
            SelectedReference(
                Reference(
                    url="https://google.example/advisory1",
                    source="google",
                    tags=["threat-intel"],
                ),
                SelectionReason.PRIORITY_TAG,
            ),
            "The attacker registers domain. The client downloads archive.exe.",
            datetime.now(UTC),
            "sha256:test1",
        ),
        FetchedAdvisory(
            SelectedReference(
                Reference(url="https://github.example/exploit", source="github", tags=["exploit"]),
                SelectionReason.PRIORITY_TAG,
            ),
            "Archive contains malicious script. Execution leads to system compromise.",
            datetime.now(UTC),
            "sha256:test2",
        ),
        FetchedAdvisory(
            SelectedReference(
                Reference(url="https://cisa.example/advisory", source="cisa", tags=["government"]),
                SelectionReason.PRIORITY_TAG,
            ),
            "The vulnerability allows remote code execution. Downloads payload.",
            datetime.now(UTC),
            "sha256:test3",
        ),
    ]

    api = MagicMock()
    # Simulate LLM response with markdown formatting (common variation)
    api.chat.completions.create = extraction_mock(
        "```json\n"
        "{\n"
        '  "steps": [\n'
        "    {\n"
        '      "step": 1,\n'
        '      "action": "Register domain for command and control",\n'
        '      "prerequisites": ["Attacker controls domain registrar"],\n'
        '      "outcome": "Domain registered and controlled",\n'
        '      "evidence": [\n'
        "        {\n"
        '          "source_url": "https://google.example/advisory1",\n'
        '          "supporting_text": "The attacker registers domain."\n'
        "        }\n"
        "      ]\n"
        "    },\n"
        "    {\n"
        '      "step": 2,\n'
        '      "action": "Download malicious archive",\n'
        '      "prerequisites": ["Network connectivity"],\n'
        '      "outcome": "Archive reaches client system",\n'
        '      "evidence": [\n'
        "        {\n"
        '          "source_url": "https://github.example/exploit",\n'
        '          "supporting_text": "Archive contains malicious script."\n'
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "```"
    )

    # Should succeed despite multiple advisories
    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", advisories)

    assert len(steps) == 2
    assert steps[0].action == "Register domain for command and control"
    assert steps[1].action == "Download malicious archive"
    # Verify we didn't lose any advisories
    assert api.chat.completions.create.await_count == 1


@pytest.mark.asyncio
async def test_error_context_includes_diagnostic_info() -> None:
    """Test that error context includes useful diagnostic information."""
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response('{"invalid": json syntax}'))

    with pytest.raises(ExtractionResponseError) as raised:
        await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    error = raised.value
    assert error.context is not None
    assert "error" in error.context
    assert error.context.get("error", "")  # Should have error details
