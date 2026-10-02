"""Preview deterministic advisory cleanup followed by MiniMax compression."""

import argparse
import asyncio
import json
from pathlib import Path

import httpx
from openai import AsyncOpenAI

from app.advisory.client import AdvisoryClient, select_references
from app.advisory.compression import (
    COMPRESSION_SYSTEM_PROMPT,
    MAX_SUCCESSFUL_ADVISORIES,
    advisory_priority,
    clean_and_deduplicate,
    split_passages,
)
from app.config import Settings
from app.ingestion.service import CVEIngestionService

SYSTEM_PROMPT = COMPRESSION_SYSTEM_PROMPT


async def compress(cve_ids: list[str], output: Path) -> None:
    settings = Settings()
    if not settings.fh_genie_key or not settings.fh_genie_base_url or not settings.fh_genie_model:
        raise RuntimeError("FH Genie configuration is required")
    llm = AsyncOpenAI(
        api_key=settings.fh_genie_key.get_secret_value(), base_url=settings.fh_genie_base_url
    )
    results: list[dict[str, object]] = []
    async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
        ingestion = CVEIngestionService(settings, client)
        advisory_client = AdvisoryClient(client, max_bytes=settings.advisory_max_bytes)
        for cve_id in cve_ids:
            cve = await ingestion.analyze(cve_id)
            fetched = []
            selected_references = sorted(
                select_references(cve.references, settings.advisory_allowed_domains),
                key=advisory_priority,
            )
            for selected in selected_references:
                try:
                    fetched.append(await advisory_client.fetch(selected))
                except Exception:
                    continue
                if len(fetched) == MAX_SUCCESSFUL_ADVISORIES:
                    break
            evidence_texts = ([cve.description] if cve.description else []) + [
                item.text for item in fetched
            ]
            blocks = clean_and_deduplicate(cve_id, evidence_texts)
            passages = split_passages(blocks)
            payload = {
                "cve_id": cve_id,
                "passages": [
                    {"id": index, "text": passage}
                    for index, passage in enumerate(passages, start=1)
                ],
            }
            response = await llm.chat.completions.create(
                model=settings.fh_genie_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
                ],
                temperature=0.0,
                max_completion_tokens=2048,
                response_format={"type": "json_object"},
                extra_body={"reasoning_split": True},
            )
            content = response.choices[0].message.content or "{}"
            summary = json.loads(content)
            results.append(
                {
                    "cve_id": cve_id,
                    "advisories_read": len(fetched),
                    "source_urls": [str(item.selected.reference.url) for item in fetched],
                    "original_chars": sum(len(item.text) for item in fetched),
                    "cleaned_chars": sum(len(item) for item in blocks),
                    "passage_count": len(passages),
                    "minimax_passage": summary.get("passage", ""),
                }
            )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("cve_ids", nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(compress(args.cve_ids, args.output))


if __name__ == "__main__":
    main()
