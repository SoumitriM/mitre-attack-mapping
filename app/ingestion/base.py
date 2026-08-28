import asyncio
from abc import ABC, abstractmethod
from typing import Any

import httpx


class SourceError(RuntimeError):
    """An authoritative source could not return usable data."""


class JSONSourceClient(ABC):
    def __init__(self, client: httpx.AsyncClient, max_retries: int = 3) -> None:
        self.client = client
        self.max_retries = max_retries

    async def _get_json(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        for attempt in range(self.max_retries + 1):
            try:
                response = await self.client.get(url, params=params, headers=headers)
                if response.status_code == 404:
                    raise SourceError(f"CVE was not found at {url}")
                response.raise_for_status()
                payload: dict[str, Any] = response.json()
                return payload
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                retryable = (
                    not isinstance(exc, httpx.HTTPStatusError)
                    or exc.response.status_code in {429, 500, 502, 503, 504}
                )
                if attempt >= self.max_retries or not retryable:
                    raise SourceError(f"Source request failed: {url}") from exc
                retry_after = 0.25 * (2**attempt)
                if isinstance(exc, httpx.HTTPStatusError):
                    header = exc.response.headers.get("Retry-After")
                    if header and header.isdigit():
                        retry_after = min(float(header), 10.0)
                await asyncio.sleep(retry_after)
        raise AssertionError("unreachable")

    @abstractmethod
    async def fetch(self, cve_id: str) -> dict[str, Any]: ...
