"""Conservative screening for descriptions that explain an exploit mechanism."""

import re

# This is an evidence-routing heuristic, not a semantic accuracy validator.
_MECHANISM = re.compile(
    r"jndi|data binding|command injection|authentication bypass|"
    r"privilege escalation|buffer overflow|stack[- ]based|heap[- ]based|"
    r"sql injection|path traversal|directory traversal|deserializ|"
    r"url protocol|unc path|ntlm|session (?:cookie|token)|"
    r"malicious code.{0,100}tarballs|tarballs.{0,100}malicious code|"
    r"build process.{0,100}(?:object file|malicious)",
    re.IGNORECASE | re.DOTALL,
)
_CONTEXT = re.compile(
    r"attacker|administrator|crafted|requests?|parameters?|execute|execution|"
    r"gain|obtain|leak|arbitrary|malicious code|library|privileges|credentials",
    re.IGNORECASE,
)


def description_has_exploit_behavior(text: str | None) -> bool:
    """Reject title-only and generic-impact descriptions before inference."""
    return bool(text and _MECHANISM.search(text) and _CONTEXT.search(text))
