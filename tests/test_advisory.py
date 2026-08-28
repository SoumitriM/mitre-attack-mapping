import socket
from typing import Any

import httpx
import pytest

from app.advisory.client import (
    AdvisoryClient,
    SelectedReference,
    UnsafeAdvisoryURL,
    select_references,
)
from app.models import Reference, SelectionReason


def reference(url: str, tags: list[str]) -> Reference:
    return Reference(url=url, source="test", tags=tags)


def test_selects_priority_tags_and_untagged_allowlisted_domains() -> None:
    selected = select_references(
        [
            reference("https://vendor.example/advisory", ["vendor advisory"]),
            reference("https://research.example/writeup", []),
            reference("https://untrusted.example/post", []),
        ],
        ["research.example"],
    )

    assert [item.reason for item in selected] == [
        SelectionReason.PRIORITY_TAG,
        SelectionReason.ALLOWLIST,
    ]


def test_deduplicates_fragment_variants_of_same_advisory() -> None:
    selected = select_references(
        [
            reference("https://research.example/writeup", []),
            reference("https://research.example/writeup/#proof", []),
        ],
        ["research.example"],
    )

    assert len(selected) == 1


@pytest.mark.asyncio
async def test_rejects_private_network_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_getaddrinfo(*args: object, **kwargs: object) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    monkeypatch.setattr("asyncio.BaseEventLoop.getaddrinfo", fake_getaddrinfo)
    selected = SelectedReference(
        reference("https://research.example/writeup", []), SelectionReason.ALLOWLIST
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(UnsafeAdvisoryURL, match="non-public"):
            await AdvisoryClient(client, max_bytes=1000).fetch(selected)


def test_html_cleaner_removes_active_and_navigation_content() -> None:
    text = AdvisoryClient._html_to_text(
        "<nav>menu</nav><h1>Exploit</h1><p>Download payload</p><script>ignore()</script>"
    )
    assert text == "Exploit\nDownload payload"
