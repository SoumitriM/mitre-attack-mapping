import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MODEL_USAGE_LOG_DIR = Path("logs") / "fh-genie"


def save_model_usage(
    stage: str,
    requested_model: str,
    response: Any,
    *,
    cve_id: str | None = None,
    item_id: str | int | None = None,
    provider: str = "fh_genie",
) -> Path:
    """Persist provider-reported token usage without logging prompts or secrets."""
    MODEL_USAGE_LOG_DIR.mkdir(parents=True, exist_ok=True)
    usage = getattr(response, "usage", None)
    usage_data = None
    if usage is not None and hasattr(usage, "model_dump"):
        try:
            usage_data = usage.model_dump(mode="json")
        except TypeError:
            usage_data = usage.model_dump()
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
    path = MODEL_USAGE_LOG_DIR / f"model_usage_{stage}_{timestamp}.json"
    path.write_text(
        json.dumps(
            {
                "stage": stage,
                "cve_id": cve_id,
                "item_id": item_id,
                "requested_model": requested_model,
                "response_model": getattr(response, "model", None),
                "provider": provider,
                "usage": usage_data,
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return path
