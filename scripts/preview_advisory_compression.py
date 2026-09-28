"""Preview deterministic advisory cleanup followed by MiniMax compression."""

import argparse
import asyncio
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import httpx
from openai import AsyncOpenAI

from app.advisory.client import AdvisoryClient, SelectedReference, select_references
from app.config import Settings
from app.ingestion.service import CVEIngestionService

MAX_SUCCESSFUL_ADVISORIES = 2
PASSAGE_CHARS = 4_000
BOILERPLATE = re.compile(
    r"(?i)(cookie|privacy policy|terms (?:of use|and conditions)|all rights reserved|"
    r"follow us|share (?:this|on)|sign (?:in|up)|subscribe|newsletter|"
    r"table of contents|skip to (?:content|main)|copyright|legal notice|"
    r"remediation|solution|workaround|fixed versions?|affected versions?|"
    r"download|contact us|about us|careers|advertis(?:e|ing))"
)
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
MIRROR_HOSTS = {"packetstormsecurity.com", "www.exploit-db.com"}

SYSTEM_PROMPT = """Compress the supplied cleaned security-advisory passages into one concise
technical passage. Include only how the attack happens: prerequisites, attacker actions,
exploitation mechanism, and direct outcome. Exclude remediation, detection guidance, attribution,
campaign narrative, and unrelated vulnerabilities. Do not add facts absent from the passages.
Return strict JSON with exactly this shape: {"passage":"..."}
"""


def clean_and_deduplicate(cve_id: str, texts: list[str]) -> list[str]:
    seen: set[str] = set()
    kept: list[str] = []
    target = cve_id.upper()
    for text in texts:
        for block in re.split(r"\n+", text):
            block = " ".join(block.split()).strip()
            if len(block) < 40 or BOILERPLATE.search(block):
                continue
            mentioned = {item.upper() for item in CVE_ID.findall(block)}
            if mentioned and target not in mentioned:
                continue
            key = re.sub(r"\W+", " ", block).lower().strip()
            if key in seen:
                continue
            seen.add(key)
            kept.append(block)
    return kept


def split_passages(blocks: list[str]) -> list[str]:
    passages: list[str] = []
    current: list[str] = []
    size = 0
    for block in blocks:
        if current and size + len(block) + 1 > PASSAGE_CHARS:
            passages.append("\n".join(current))
            current, size = [], 0
        current.append(block)
        size += len(block) + 1
    if current:
        passages.append("\n".join(current))
    return passages


def advisory_priority(selected: SelectedReference) -> tuple[int, int, str]:
    reference = selected.reference
    tags = {tag.lower() for tag in reference.tags}
    url = str(reference.url)
    host = (urlparse(url).hostname or "").lower()
    vendor = bool(tags & {"vendor advisory", "vendor-advisory"})
    mirror = host in MIRROR_HOSTS
    return (0 if vendor else 1, 1 if mirror else 0, url)


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
            blocks = clean_and_deduplicate(cve_id, [item.text for item in fetched])
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
