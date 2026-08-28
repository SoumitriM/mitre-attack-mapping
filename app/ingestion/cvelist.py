import json
from pathlib import Path
from typing import Any

from app.ingestion.base import SourceError


class CVEListV5Client:
    """Read a CVE record from a pinned local CVE List V5 snapshot."""

    def __init__(self, root: Path) -> None:
        self.root = root

    async def fetch(self, cve_id: str) -> dict[str, Any]:
        _, year, sequence = cve_id.split("-")
        bucket = f"{sequence[:-3]}xxx" if len(sequence) > 3 else "0xxx"
        candidates = (
            self.root / "cves" / year / bucket / f"{cve_id}.json",
            self.root / year / bucket / f"{cve_id}.json",
        )
        path = next((item for item in candidates if item.is_file()), None)
        if path is None and self.root.is_dir():
            pattern = f"*/extracted/*/cves/{year}/{bucket}/{cve_id}.json"
            path = next(self.root.glob(pattern), None)
        if path is None:
            raise SourceError(f"CVE List V5 has no local record for {cve_id}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SourceError(f"CVE List V5 record is unreadable for {cve_id}") from exc
        if not isinstance(payload, dict):
            raise SourceError(f"CVE List V5 record is invalid for {cve_id}")
        return payload
