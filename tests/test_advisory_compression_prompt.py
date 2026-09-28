from scripts.preview_advisory_compression import MAX_SUCCESSFUL_ADVISORIES, SYSTEM_PROMPT

NORMALIZED_PROMPT = " ".join(SYSTEM_PROMPT.lower().split())


def test_preview_reads_at_most_five_successful_advisories() -> None:
    assert MAX_SUCCESSFUL_ADVISORIES == 5


def test_compression_prompt_preserves_attack_chain_detail() -> None:
    required_instructions = (
        "prerequisite or exposed component",
        "attacker-controlled input or concrete attacker action",
        "how the vulnerable component processes that input",
        "each source-supported intermediate transition",
        "immediate technical result",
        "post-exploitation actions or effects",
        "chronological order",
        "preserve distinct attack stages",
    )

    for instruction in required_instructions:
        assert instruction in NORMALIZED_PROMPT


def test_compression_prompt_forbids_unsupported_or_irrelevant_content() -> None:
    required_guardrails = (
        "do not use outside knowledge",
        "infer hidden implementation details",
        "cwe label",
        "affected-version range is ambiguous",
        "do not claim that an observed action is required or universal",
        "remediation",
        "detection guidance",
        "attribution",
        "campaign narrative",
    )

    for guardrail in required_guardrails:
        assert guardrail in NORMALIZED_PROMPT


def test_compression_prompt_keeps_strict_single_field_json_contract() -> None:
    assert '{"passage":"..."}' in SYSTEM_PROMPT
    assert "exactly one key" in SYSTEM_PROMPT
    assert "no Markdown or commentary" in SYSTEM_PROMPT
