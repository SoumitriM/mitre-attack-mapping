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
from app.models import ExploitStepEnvelope, Reference, SelectionReason


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


@pytest.fixture(autouse=True)
def isolate_fh_genie_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fh_genie_module, "RESPONSE_LOG_DIR", tmp_path)


def grounding_response(
    supported: bool = True,
    confidence: float = 0.90,
    reasoning: str = "The advisory supports the same attacker action.",
) -> SimpleNamespace:
    return response(
        json.dumps({
            "supported": supported,
            "confidence": confidence,
            "reasoning": reasoning,
        })
    )


def evidence_result(
    supporting_text: str,
    source_url: str = "https://research.example/advisory",
) -> ExploitStepEnvelope:
    return ExploitStepEnvelope.model_validate({
        "steps": [{
            "step": 1,
            "action": "Register domain",
            "prerequisites": [],
            "outcome": "Domain controlled",
            "evidence": [{"source_url": source_url, "supporting_text": supporting_text}],
        }]
    })


def extraction_and_grounding_mock(
    extraction_content: str,
    grounding: SimpleNamespace | None = None,
) -> AsyncMock:
    async def create(**kwargs: object) -> SimpleNamespace:
        messages = kwargs["messages"]
        assert isinstance(messages, list)
        if "validate whether extracted exploit evidence" in messages[0]["content"]:
            return grounding or grounding_response()
        return response(extraction_content)

    return AsyncMock(side_effect=create)


def test_v5_prompt_requires_atomic_deduplicated_exploit_steps() -> None:
    assert PROMPT_VERSION == "exploit-steps-v5"
    assert "one coherent attacker behavior" in SYSTEM_PROMPT
    assert "Split a sequence into separate steps" in SYSTEM_PROMPT
    assert "normalized CVE description" in SYSTEM_PROMPT
    assert "duplicate steps" in SYSTEM_PROMPT


@pytest.mark.asyncio
async def test_extracts_from_normalized_description_without_advisory() -> None:
    description = DescriptionEvidence(
        source_name="NVD",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-33557",
        text="An attacker can generate a JWT token and the broker will accept it.",
    )
    api = MagicMock()
    api.chat.completions.create = extraction_and_grounding_mock(
        '{"steps":[{"step":1,"action":"Forge JWT token","prerequisites":[],'
        '"outcome":"Broker accepts token","evidence":[{"source_url":'
        '"https://nvd.nist.gov/vuln/detail/CVE-2026-33557","supporting_text":'
        '"An attacker can generate a JWT token and the broker will accept it."}]}]}'
    )
    steps = await FHGenieEvidenceAgent(settings(), api).extract(
        "CVE-2026-33557", [], description
    )
    payload = json.loads(api.chat.completions.create.await_args.kwargs["messages"][1]["content"])
    assert steps[0].action == "Forge JWT token"
    assert payload["description_evidence"]["source_name"] == "NVD"
    assert payload["advisories"] == []


@pytest.mark.asyncio
async def test_extracts_sequential_grounded_steps() -> None:
    api = MagicMock()
    api.chat.completions.create = extraction_and_grounding_mock(
        '{"steps":[{"step":1,"action":"Register domain","prerequisites":[], '
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}]}'
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2026-22306", [advisory()])

    assert steps[0].action == "Register domain"


@pytest.mark.asyncio
async def test_grounding_accepts_equivalent_trailing_slash_url() -> None:
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

    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=grounding_response())
    assert await FHGenieEvidenceAgent(settings(), api)._is_grounded(result, [advisory()])


@pytest.mark.asyncio
async def test_extraction_pipeline_skips_grounding() -> None:
    api = MagicMock()
    api.chat.completions.create = extraction_and_grounding_mock(
        '{"steps":[{"step":1,"action":"Invented","prerequisites":[], '
        '"outcome":"Invented","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":"private invented text"}]}]}',
        grounding_response(False, 0.05, "The technical claim is absent."),
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract(
        "CVE-2026-22306", [advisory()]
    )

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
    api.chat.completions.create = extraction_and_grounding_mock(
        '```json\n'
        '{"steps":[{"step":1,"action":"Register domain","prerequisites":[], '
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}]}\n'
        '```'
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract("CVE-2025-0282", [advisory()])

    assert len(steps) == 1
    assert steps[0].action == "Register domain"


@pytest.mark.asyncio
async def test_handles_json_with_text_before_object() -> None:
    """Test that JSON preceded by explanatory text is extracted."""
    api = MagicMock()
    api.chat.completions.create = extraction_and_grounding_mock(
        'Here is the extracted exploit sequence:\n'
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
    api.chat.completions.create = extraction_and_grounding_mock(
        '```\n'
        '{"steps":[{"step":1,"action":"Register domain","prerequisites":[], '
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}]}\n'
        '```'
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
async def test_retries_bare_step_with_explicit_envelope_instruction() -> None:
    bare_step = (
        '{"step":1,"action":"Register domain","prerequisites":[],'
        '"outcome":"Domain controlled","evidence":[{"source_url":'
        '"https://research.example/advisory","supporting_text":'
        '"The attacker registers the abandoned domain."}]}'
    )
    envelope = f'{{"steps":[{bare_step}]}}'
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        side_effect=[response(bare_step), response(envelope)]
    )

    steps = await FHGenieEvidenceAgent(settings(), api).extract(
        "CVE-2025-0282", [advisory()]
    )

    assert steps[0].action == "Register domain"
    retry_messages = api.chat.completions.create.await_args_list[1].kwargs["messages"]
    assert "Do not return a bare step" in retry_messages[-1]["content"]


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
    api.chat.completions.create = extraction_and_grounding_mock(
        '```json\n'
        '{\n'
        '  "steps": [\n'
        '    {\n'
        '      "step": 1,\n'
        '      "action": "Register domain for command and control",\n'
        '      "prerequisites": ["Attacker controls domain registrar"],\n'
        '      "outcome": "Domain registered and controlled",\n'
        '      "evidence": [\n'
        '        {\n'
        '          "source_url": "https://google.example/advisory1",\n'
        '          "supporting_text": "The attacker registers domain."\n'
        '        }\n'
        '      ]\n'
        '    },\n'
        '    {\n'
        '      "step": 2,\n'
        '      "action": "Download malicious archive",\n'
        '      "prerequisites": ["Network connectivity"],\n'
        '      "outcome": "Archive reaches client system",\n'
        '      "evidence": [\n'
        '        {\n'
        '          "source_url": "https://github.example/exploit",\n'
        '          "supporting_text": "Archive contains malicious script."\n'
        '        }\n'
        '      ]\n'
        '    }\n'
        '  ]\n'
        '}\n'
        '```'
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


@pytest.mark.asyncio
async def test_grounding_accepts_same_meaning_with_different_wording() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=grounding_response())
    agent = FHGenieEvidenceAgent(settings(), api)

    invalid = await agent._unsupported_steps(
        evidence_result("An adversary takes control of the expired domain."),
        [advisory()],
    )

    assert invalid == []
    assert api.chat.completions.create.await_args.kwargs["temperature"] == 0.0


@pytest.mark.asyncio
async def test_grounding_rejects_unsupported_technical_claim() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=grounding_response(
        supported=False,
        confidence=0.04,
        reasoning="The evidence adds a PowerShell execution fact absent from the source.",
    ))

    invalid = await FHGenieEvidenceAgent(settings(), api)._unsupported_steps(
        evidence_result("The attacker executes payload.exe with PowerShell."),
        [advisory()],
    )

    assert invalid == [1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("confidence", "expected"),
    [(0.69, [1]), (0.70, [])],
    ids=["confidence-0.69-rejected", "confidence-0.70-accepted"],
)
async def test_grounding_confidence_threshold(
    confidence: float,
    expected: list[int],
) -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(
        return_value=grounding_response(confidence=confidence)
    )

    invalid = await FHGenieEvidenceAgent(settings(), api)._unsupported_steps(
        evidence_result("An adversary takes control of the expired domain."),
        [advisory()],
    )

    assert invalid == expected


@pytest.mark.asyncio
async def test_grounding_requires_supported_flag_and_confidence() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=grounding_response(
        supported=False,
        confidence=0.70,
        reasoning="Deliberately inconsistent output used to verify the decision rule.",
    ))

    invalid = await FHGenieEvidenceAgent(settings(), api)._unsupported_steps(
        evidence_result("An adversary takes control of the expired domain."),
        [advisory()],
    )

    assert invalid == [1]


@pytest.mark.asyncio
async def test_grounding_keeps_step_when_one_evidence_item_survives() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(side_effect=[
        grounding_response(
            supported=False,
            confidence=0.95,
            reasoning="The evidence adds a technical fact absent from the advisory.",
        ),
        grounding_response(supported=True, confidence=0.70),
    ])
    result = ExploitStepEnvelope.model_validate({
        "steps": [{
            "step": 1,
            "action": "Register domain",
            "prerequisites": [],
            "outcome": "Domain controlled",
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "The attacker uses PowerShell.",
                },
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "An adversary takes control of the expired domain.",
                },
            ],
        }]
    })

    invalid = await FHGenieEvidenceAgent(settings(), api)._unsupported_steps(
        result,
        [advisory()],
    )

    assert invalid == []
    assert [item.supporting_text for item in result.steps[0].evidence] == [
        "An adversary takes control of the expired domain."
    ]


@pytest.mark.asyncio
async def test_grounding_appends_accepted_and_rejected_json_records(tmp_path: Path) -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(side_effect=[
        grounding_response(False, 0.95, "The source does not support this claim."),
        grounding_response(True, 0.70, "The source supports the same action."),
    ])
    result = ExploitStepEnvelope.model_validate({
        "steps": [{
            "step": 1,
            "action": "Register domain",
            "prerequisites": [],
            "outcome": "Domain controlled",
            "evidence": [
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "Unsupported claim.",
                },
                {
                    "source_url": "https://research.example/advisory",
                    "supporting_text": "Equivalent supported claim.",
                },
            ],
        }]
    })

    await FHGenieEvidenceAgent(settings(), api)._unsupported_steps(
        result,
        [advisory()],
        "CVE-2026-22306",
    )

    log_file = tmp_path / "CVE-2026-22306_grounding.json"
    records = json.loads(log_file.read_text(encoding="utf-8"))
    assert [record["accepted"] for record in records] == [False, True]
    assert records[0]["supported"] is False
    assert records[0]["confidence"] == 0.95
    assert records[1]["supported"] is True
    assert records[1]["confidence"] == 0.70
    assert all(record["cve_id"] == "CVE-2026-22306" for record in records)
    assert all(record["timestamp"] for record in records)


@pytest.mark.asyncio
async def test_grounding_rejects_source_url_not_found_without_model_call() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock()

    invalid = await FHGenieEvidenceAgent(settings(), api)._unsupported_steps(
        evidence_result(
            "The attacker registers the abandoned domain.",
            source_url="https://other.example/advisory",
        ),
        [advisory()],
    )

    assert invalid == [1]
    api.chat.completions.create.assert_not_awaited()


@pytest.mark.asyncio
async def test_grounding_handles_malformed_json_safely() -> None:
    api = MagicMock()
    api.chat.completions.create = AsyncMock(return_value=response("not JSON"))

    invalid = await FHGenieEvidenceAgent(settings(), api)._unsupported_steps(
        evidence_result("The attacker registers the abandoned domain."),
        [advisory()],
    )

    assert invalid == [1]
