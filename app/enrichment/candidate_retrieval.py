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
RERANK_LIMIT = 5
RETRIEVAL_LOG_DIR = Path("logs") / "attack-retrieval"
RERANK_RESPONSE_LOG_DIR = Path("logs") / "fh-genie"

RERANK_SYSTEM_PROMPT = """
You are a CLOSED-SET reranker for MITRE Enterprise ATT&CK candidates for ONE atomic exploit step.

Your task is ONLY to reorder and score the candidate techniques supplied in the input.

CRITICAL CONSTRAINTS:

* You MUST return ONLY MITRE technique IDs that appear exactly in the supplied candidate list.
* NEVER introduce, infer, substitute, correct, expand, or retrieve any ATT&CK technique ID
  that is not supplied.
* Even if you know a more accurate ATT&CK technique, you MUST NOT return it unless its ID
  appears in the supplied candidates.
* Do not replace a supplied parent technique with an unsupplied sub-technique.
* Do not replace a supplied sub-technique with an unsupplied parent technique.
* Treat the supplied candidate IDs as an exhaustive closed set.
* Before producing the final JSON, verify that every returned mitre_technique_id exists
  verbatim in the supplied candidate list.

RANKING CRITERIA:
Rank candidates by semantic equivalence to the OBSERVED ATTACKER BEHAVIOR, not by
vulnerability category or shared terminology.

For each supplied candidate, evaluate:

1. REQUIRED BEHAVIOR
   Identify the defining behavior required by the ATT&CK technique.
   A candidate should rank highly only if that defining behavior is explicitly observed
   or strongly supported by the exploit-step evidence.

2. MECHANISM MATCH
   The attack mechanism must match, not merely the attacker's broad objective.
   Similar words, outcomes, or security concepts are insufficient.

3. ATTACK CONTEXT
   Consider whether the behavior occurs during reconnaissance, initial access,
   execution, persistence, privilege escalation, defense evasion, discovery,
   lateral movement, command and control, or another relevant context.

4. OUTCOME MATCH
   Consider whether the observed result matches the purpose of the candidate technique.
   Do not infer outcomes that are not stated or strongly implied.

5. PLATFORM COMPATIBILITY
   Use supplied platform metadata when available.
   Strongly penalize candidates whose required platform or technology is incompatible
   with the observed system.

SCORING GUIDANCE:

* 0.90-1.00: Direct behavioral and mechanistic match.
* 0.75-0.89: Strong match with minor ambiguity.
* 0.50-0.74: Plausibly related but incomplete or less specific.
* 0.30-0.49: Weak relationship; mechanism or context differs.
* 0.00-0.29: Defining behavior is absent, contradicted, or platform-incompatible.

IMPORTANT:

* Do not reward a candidate merely because words in its name appear in the exploit step.
* Do not infer undocumented behavior just to make a technique fit.
* If a technique requires a specific mechanism that is absent, score it <= 0.30.
* If the platform is clearly incompatible, score it <= 0.20.
* Prefer a broader supplied parent technique over an incorrect supplied sub-technique
  when the sub-technique's defining mechanism is not present.

OUTPUT RULES:

* Return exactly the 5 highest-ranked SUPPLIED candidates.
* If fewer than 5 candidates were supplied, return every supplied candidate exactly once.
* Never return duplicate IDs.
* Never return an ID outside the supplied candidate list.
* The five returned candidates may all have low scores if none is a strong match.
* Do not manufacture a better candidate to compensate for poor retrieval.
* Keep each reasoning value to one short sentence.
* Return JSON only.
* Do not include markdown, commentary, code fences, or additional keys.

Return exactly this JSON shape, replacing SUPPLIED_ID with an ID copied verbatim
from ALLOWED_TECHNIQUE_IDS in the final instruction:

{"candidates":[
{
"mitre_technique_id":"SUPPLIED_ID",
"reasoning":"One short sentence comparing the supplied technique with the observed behavior.",
"rerank_score":0.94
}
]}
""".strip()


def rerank_system_prompt(candidates: list[dict[str, Any]], expected_count: int) -> str:
    """Bind the closed-set instructions to the IDs supplied for this request."""
    allowed_ids = [str(item["mitre_technique_id"]) for item in candidates]
    return (
        f"{RERANK_SYSTEM_PROMPT}\n\n"
        "FINAL CLOSED-SET INSTRUCTION:\n"
        f"ALLOWED_TECHNIQUE_IDS={json.dumps(allowed_ids)}\n"
        f"Return exactly {expected_count} candidates. Copy every technique ID verbatim "
        "from ALLOWED_TECHNIQUE_IDS. Any other ID makes the entire response invalid."
    )



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
            {
                "role": "system",
                "content": rerank_system_prompt(candidates, expected_count),
            },
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
