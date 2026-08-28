import asyncio
import hashlib
import ipaddress
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.models import Reference, SelectionReason

PRIORITY_TAGS = {
    "vendor advisory",
    "vendor-advisory",
    "third party advisory",
    "third-party-advisory",
    "exploit",
    "patch",
}
SUPPORTED_TYPES = {"text/html", "text/plain", "application/xhtml+xml"}


class UnsafeAdvisoryURL(ValueError):
    pass


class AdvisoryFetchError(RuntimeError):
    pass


class UnsupportedAdvisoryContent(AdvisoryFetchError):
    pass


@dataclass(frozen=True)
class SelectedReference:
    reference: Reference
    reason: SelectionReason


@dataclass(frozen=True)
class FetchedAdvisory:
    selected: SelectedReference
    text: str
    retrieved_at: datetime
    checksum: str


def select_references(
    references: list[Reference], allowed_domains: list[str]
) -> list[SelectedReference]:
    allowed = {item.lower().lstrip(".") for item in allowed_domains}
    selected: dict[str, SelectedReference] = {}
    for reference in references:
        url = str(reference.url)
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        tags = {tag.lower() for tag in reference.tags}
        tagged = bool(tags & PRIORITY_TAGS)
        allowlisted = any(host == domain or host.endswith(f".{domain}") for domain in allowed)
        if not tagged and not allowlisted:
            continue
        reason = (
            SelectionReason.PRIORITY_TAG_AND_ALLOWLIST
            if tagged and allowlisted
            else SelectionReason.PRIORITY_TAG
            if tagged
            else SelectionReason.ALLOWLIST
        )
        canonical_key = urldefrag(url).url.rstrip("/").lower()
        selected.setdefault(canonical_key, SelectedReference(reference, reason))
    return sorted(
        selected.values(),
        key=lambda item: (item.reason == SelectionReason.ALLOWLIST, str(item.reference.url)),
    )


def normalize_evidence_text(value: str) -> str:
    return " ".join(value.split())


class AdvisoryClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        max_bytes: int,
        max_redirects: int = 5,
    ) -> None:
        self._client = client
        self._max_bytes = max_bytes
        self._max_redirects = max_redirects

    async def fetch(self, selected: SelectedReference) -> FetchedAdvisory:
        url = str(selected.reference.url)
        for _ in range(self._max_redirects + 1):
            await self._validate_public_url(url)
            try:
                async with self._client.stream("GET", url, follow_redirects=False) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise AdvisoryFetchError("advisory redirect has no location")
                        url = urljoin(url, location)
                        continue
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                    if content_type not in SUPPORTED_TYPES:
                        raise UnsupportedAdvisoryContent(
                            f"unsupported advisory content type: {content_type or 'unknown'}"
                        )
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self._max_bytes:
                            raise AdvisoryFetchError("advisory exceeds configured size limit")
            except httpx.HTTPError as exc:
                raise AdvisoryFetchError("advisory request failed") from exc
            text = bytes(body).decode(response.encoding or "utf-8", errors="replace")
            if content_type in {"text/html", "application/xhtml+xml"}:
                text = self._html_to_text(text)
            else:
                text = normalize_evidence_text(text)
            if not text:
                raise AdvisoryFetchError("advisory contains no usable text")
            checksum = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
            return FetchedAdvisory(selected, text, datetime.now(UTC), checksum)
        raise AdvisoryFetchError("advisory exceeded redirect limit")

    @staticmethod
    def _html_to_text(value: str) -> str:
        soup = BeautifulSoup(value, "html.parser")
        for element in soup(["script", "style", "nav", "noscript", "svg"]):
            element.decompose()
        elements = soup.find_all(["h1", "h2", "h3", "p", "li", "pre"])
        blocks = [normalize_evidence_text(item.get_text(" ", strip=True)) for item in elements]
        return "\n".join(dict.fromkeys(item for item in blocks if item))

    @staticmethod
    async def _validate_public_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise UnsafeAdvisoryURL("advisory URL must be absolute HTTP(S)")
        try:
            records = await asyncio.get_running_loop().getaddrinfo(
                parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise UnsafeAdvisoryURL("advisory hostname could not be resolved") from exc
        addresses = {item[4][0] for item in records}
        if not addresses or any(not ipaddress.ip_address(item).is_global for item in addresses):
            raise UnsafeAdvisoryURL("advisory URL resolves to a non-public address")
