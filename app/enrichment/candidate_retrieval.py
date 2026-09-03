import json
import logging
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.models import ExploitStep

logger = logging.getLogger(__name__)
VECTOR_RETRIEVAL_LIMIT = 20
RERANK_LIMIT = 10
RETRIEVAL_LOG_DIR = Path("logs") / "attack-retrieval"
RERANK_RESPONSE_LOG_DIR = Path("logs") / "fh-genie"

RERANK_SYSTEM_PROMPT = """
You rerank supplied MITRE Enterprise ATT&CK candidates for ONE atomic exploit step.
Rank semantic equivalence to the observed attacker behavior, not the vulnerability
category. Do not favor candidates based only on shared keywords. You may use tactic
and platform metadata as context, but never as hard pre-filters. Do not invent or
retrieve techniques: return only IDs in the supplied candidate list.

Return exactly the 10 best supplied candidates, ordered best to worst. If fewer than
10 seem plausibly relevant, still return the 10 highest-ranked supplied candidates.
If fewer than 10 candidates were supplied, return every supplied candidate once.
Keep each reasoning value to one short sentence so the complete JSON response fits
within the output limit.

Return JSON only in this schema:
{"candidates":[{"mitre_technique_id":"T1059.003","reasoning":"...","rerank_score":0.94}]}
""".strip()


class EmbeddingData(Protocol):
    embedding: list[float]


class EmbeddingResponse(Protocol):
    data: list[EmbeddingData]


class EmbeddingsAPI(Protocol):
    async def create(self, **kwargs: Any) -> EmbeddingResponse: ...


class EmbeddingClient(Protocol):
    embeddings: EmbeddingsAPI


class RerankClient(Protocol):
    chat: Any


class RerankedCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mitre_technique_id: str
    reasoning: str = Field(min_length=1)
    rerank_score: float = Field(ge=0, le=1)


class RerankEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidates: list[RerankedCandidate]


def behavior_query(step: ExploitStep) -> str:
    """Build the embedding query from raw atomic-step fields only."""
    return " ".join(
        text
        for text in (
            step.action,
            *step.prerequisites,
            step.outcome,
            *(item.supporting_text for item in step.evidence),
        )
        if text
    ).strip()


def canonical_attack_document(record: dict[str, Any]) -> str:
    """Build the sole canonical representation used for ATT&CK embeddings."""
    tactics = record.get("tactics") or []
    tactic_names = [
        str(item.get("name") or "") if isinstance(item, dict) else str(item) for item in tactics
    ]
    platforms = [str(item) for item in (record.get("platforms") or [])]
    return "\n".join(
        (
            f"MITRE ATT&CK Technique: {record.get('mitre_technique_id') or ''}",
            f"Name: {record.get('name') or ''}",
            f"Tactics: {', '.join(filter(None, tactic_names))}",
            f"Platforms: {', '.join(platforms)}",
            f"Description: {record.get('description') or ''}",
        )
    )


def embedding_cache_key(record: dict[str, Any], model: str) -> str:
    return f"{model}\0{canonical_attack_document(record)}"


def vector_cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise ValueError("Embedding vectors have different dimensions")
    denominator = math.sqrt(sum(v * v for v in left)) * math.sqrt(sum(v * v for v in right))
    return (
        sum(a * b for a, b in zip(left, right, strict=True)) / denominator if denominator else 0.0
    )


async def embed_texts(
    client: EmbeddingClient, model: str, inputs: list[str], *, batch_size: int = 64
) -> list[list[float]]:
    vectors: list[list[float]] = []
    for offset in range(0, len(inputs), batch_size):
        batch = inputs[offset : offset + batch_size]
        response = await client.embeddings.create(model=model, input=batch)
        batch_vectors = [item.embedding for item in response.data]
        if len(batch_vectors) != len(batch):
            raise ValueError("Embedding response count does not match embedding request")
        vectors.extend(batch_vectors)
    return vectors


def vector_similarity_scores(
    query_vector: list[float],
    records: list[dict[str, Any]],
    technique_vectors: dict[str, list[float]],
) -> dict[str, float]:
    return {
        record["mitre_technique_id"]: vector_cosine(query_vector, vector)
        for record in records
        if (vector := technique_vectors.get(record["mitre_technique_id"])) is not None
    }


def top_vector_candidates(
    records: list[dict[str, Any]],
    vector_scores: dict[str, float],
    limit: int = VECTOR_RETRIEVAL_LIMIT,
) -> list[dict[str, Any]]:
    if limit <= 0:
        raise ValueError("Vector retrieval limit must be greater than zero")
    by_id = {record["mitre_technique_id"]: record for record in records}
    ranked = sorted(
        (
            (technique_id, score)
            for technique_id, score in vector_scores.items()
            if technique_id in by_id
        ),
        key=lambda item: (-item[1], item[0]),
    )[:limit]
    return [{**by_id[technique_id], "vector_score": score} for technique_id, score in ranked]


def _extract_json(content: str) -> str:
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", content.strip(), re.DOTALL)
    text = fenced.group(1) if fenced else content
    start = text.find("{")
    if start < 0:
        raise ValueError("Reranker response contains no JSON object")
    value, _ = json.JSONDecoder().raw_decode(text[start:])
    return json.dumps(value)


def _save_invalid_rerank_response(step: ExploitStep, content: str, error: Exception) -> Path:
    RERANK_RESPONSE_LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
    path = RERANK_RESPONSE_LOG_DIR / f"step_{step.step}_rerank_invalid_{timestamp}.txt"
    try:
        path.write_text(
            f"Step: {step.step}\nAction: {step.action}\nError: {error}\n\n{content}",
            encoding="utf-8",
        )
    except OSError:
        logger.exception("Failed to write invalid reranker response log")
    return path


async def rerank_candidates(
    client: RerankClient,
    model: str,
    step: ExploitStep,
    candidates: list[dict[str, Any]],
    limit: int = RERANK_LIMIT,
) -> tuple[list[dict[str, Any]], list[RerankedCandidate]]:
    """Use FH Genie to order only the supplied vector candidate set."""
    expected_count = min(limit, len(candidates))
    payload = {
        "exploit_step": step.model_dump(mode="json"),
        "candidates": [
            {
                "mitre_technique_id": item["mitre_technique_id"],
                "name": item.get("name", ""),
                "description": item.get("description", ""),
                "tactics": item.get("tactics", []),
                "platforms": item.get("platforms", []),
                "vector_score": item["vector_score"],
            }
            for item in candidates
        ],
    }
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": RERANK_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
        temperature=0.0,
        max_completion_tokens=8192,
        extra_body={"reasoning_split": True},
    )
    content = response.choices[0].message.content
    if not content:
        raise ValueError("Empty FH Genie reranker response")
    try:
        envelope = RerankEnvelope.model_validate_json(_extract_json(content))
    except (ValueError, ValidationError) as exc:
        log_file = _save_invalid_rerank_response(step, content, exc)
        raise ValueError(
            f"Invalid FH Genie reranker response: {exc}; raw response: {log_file}"
        ) from exc
    supplied = {item["mitre_technique_id"]: item for item in candidates}
    returned_ids = [item.mitre_technique_id for item in envelope.candidates]
    if len(returned_ids) != expected_count or len(set(returned_ids)) != expected_count:
        raise ValueError(
            f"FH Genie reranker must return exactly {expected_count} unique candidates"
        )
    unknown = set(returned_ids) - supplied.keys()
    if unknown:
        raise ValueError(f"FH Genie reranker returned unsupplied candidate IDs: {sorted(unknown)}")
    return [supplied[item_id] for item_id in returned_ids], envelope.candidates


def save_retrieval_log(
    *,
    cve_id: str | None,
    step: ExploitStep,
    query_text: str,
    vector_candidates: list[dict[str, Any]],
    reranked: list[RerankedCandidate],
) -> Path:
    RETRIEVAL_LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
    path = RETRIEVAL_LOG_DIR / f"{cve_id or 'unknown-cve'}_step_{step.step}_{timestamp}.json"
    payload = {
        "cve_id": cve_id,
        "step": step.step,
        "action": step.action,
        "query_text": query_text,
        "vector_candidates": [
            {
                "rank": rank,
                "id": item["mitre_technique_id"],
                "name": item.get("name", ""),
                "vector_score": round(item["vector_score"], 6),
            }
            for rank, item in enumerate(vector_candidates, start=1)
        ],
        "reranked_candidates": [
            {"rank": rank, "id": item.mitre_technique_id, "rerank_score": item.rerank_score}
            for rank, item in enumerate(reranked, start=1)
        ],
    }
    try:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError:
        logger.exception("Failed to write ATT&CK retrieval log")
    return path
