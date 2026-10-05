"""Basic length screening for description-first extraction."""


def description_is_substantive(text: str | None) -> bool:
    """Attempt extraction from descriptions with at least eight whitespace-separated words.

    This only filters empty and very short text. The extractor determines whether
    the description supplies evidence for exploit steps; no mechanism vocabulary
    is required.
    """
    return bool(text and len(text.split()) >= 8)
