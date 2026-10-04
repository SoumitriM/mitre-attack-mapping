import asyncio
import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from neo4j import AsyncDriver

from app.enrichment.candidate_retrieval import (
    BM25_RETRIEVAL_LIMIT,
    RERANK_INPUT_LIMIT,
    RERANK_LIMIT,
    VECTOR_RETRIEVAL_LIMIT,
    EmbeddingClient,
    RerankClient,
    attack_embedding_documents,
    behavior_query,
    bm25_scores,
    combine_candidates,
    embed_texts,
    embedding_cache_key,
    rerank_candidates,
    save_retrieval_log,
    top_bm25_candidates,
    top_vector_candidates,
    vector_similarity_scores,
)
from app.models import (
    AttackCandidate,
    ExploitStep,
)

logger = logging.getLogger(__name__)

CTID_NORMALIZED_ROLES = {
    "exploitation_behaviors": "exploitation",
    "primary_capabilities": "primary_impact",
    "secondary_behaviors": "secondary_impact",
}
CTID_RETRIEVAL_LIMIT = 20
CTID_FINAL_CANDIDATE_LIMIT = 12
CTID_PROCEDURE_EXAMPLE_LIMIT = 3
CTID_PROCEDURE_EXAMPLE_MAX_CHARS = 500


class GraphUnavailable(RuntimeError):
    pass


class TaxonomyUnavailable(GraphUnavailable):
    pass


class GraphRepository:
    _description_embedding_cache: dict[str, dict[str, tuple[str, list[list[float]]]]] = {}
    CONSTRAINTS = (
        "CREATE CONSTRAINT technique_id IF NOT EXISTS "
        "FOR (n:AttackTechnique) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (n:AttackTactic) REQUIRE n.id IS UNIQUE",
    )

    def __init__(
        self,
        driver: AsyncDriver,
        embedding_client: EmbeddingClient | None = None,
        embedding_model: str | None = None,
        rerank_client: RerankClient | None = None,
        rerank_model: str | None = None,
        attack_embedding_cache_path: Path | None = None,
    ) -> None:
        self._driver = driver
        self._embedding_client = embedding_client
        self._embedding_model = embedding_model
        self._rerank_client = rerank_client or cast(RerankClient | None, embedding_client)
        self._rerank_model = rerank_model or embedding_model
        self._attack_embedding_cache_path = attack_embedding_cache_path
        self._technique_embeddings: dict[str, tuple[str, list[list[float]]]] = {}
        self._embedding_lock = asyncio.Lock()

    def _load_description_embedding_cache(self) -> None:
        if self._embedding_model is None or self._attack_embedding_cache_path is None:
            return
        path = self._attack_embedding_cache_path
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("embedding_model") != self._embedding_model:
                return
            entries = payload["techniques"]
            self._description_embedding_cache[self._embedding_model] = {
                technique_id: (item["cache_key"], item["vectors"])
                for technique_id, item in entries.items()
            }
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise GraphUnavailable(f"ATT&CK embedding cache could not be loaded: {path}") from exc

    async def initialize_description_embedding_cache(self, *, batch_size: int = 64) -> int:
        """Build and persist corpus embeddings outside the per-CVE request path."""
        if self._embedding_client is None or self._embedding_model is None:
            raise GraphUnavailable("FH Genie embedding retrieval is not configured")
        if self._attack_embedding_cache_path is None:
            raise GraphUnavailable("ATT&CK embedding cache path is not configured")
        records = await self._active_attack_records()
        model_cache: dict[str, tuple[str, list[list[float]]]] = {}
        pending: list[tuple[dict[str, Any], list[str]]] = [
            (record, attack_embedding_documents(record)) for record in records
        ]
        texts = [text for _, documents in pending for text in documents]
        vectors: list[list[float]] = []
        for offset in range(0, len(texts), batch_size):
            vectors.extend(
                await embed_texts(
                    self._embedding_client,
                    self._embedding_model,
                    texts[offset : offset + batch_size],
                )
            )
        vector_offset = 0
        for record, documents in pending:
            record_vectors = vectors[vector_offset : vector_offset + len(documents)]
            vector_offset += len(documents)
            model_cache[record["mitre_technique_id"]] = (
                embedding_cache_key(record, self._embedding_model),
                record_vectors,
            )
        path = self._attack_embedding_cache_path
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = path.with_suffix(f"{path.suffix}.tmp")
        temporary_path.write_text(
            json.dumps(
                {
                    "embedding_model": self._embedding_model,
                    "techniques": {
                        technique_id: {"cache_key": item[0], "vectors": item[1]}
                        for technique_id, item in model_cache.items()
                    },
                }
            ),
            encoding="utf-8",
        )
        temporary_path.replace(path)
        self._description_embedding_cache[self._embedding_model] = model_cache
        return len(model_cache)

    async def initialize(self) -> None:
        try:
            async with self._driver.session() as session:
                for query in self.CONSTRAINTS:
                    await (await session.run(query)).consume()
        except Exception as exc:
            raise GraphUnavailable("Neo4j initialization failed") from exc

    async def verify_taxonomy(self) -> None:
        try:
            async with self._driver.session() as session:
                record = await (
                    await session.run(
                        "MATCH (r:DatasetRelease) WHERE r.name = 'ATT&CK' "
                        "RETURN collect(DISTINCT r.name) AS names"
                    )
                ).single()
            if record is None or set(record["names"]) != {"ATT&CK"}:
                raise TaxonomyUnavailable("required ATT&CK dataset is not loaded")
        except TaxonomyUnavailable:
            raise
        except Exception as exc:
            raise GraphUnavailable("Neo4j taxonomy check failed") from exc

    async def attack_candidates(
        self,
        step: ExploitStep,
        cve_id: str | None = None,
        *,
        limit: int = 10,
    ) -> list[AttackCandidate]:
        """Retrieve ATT&CK candidates using BM25 and semantic vector similarity.

        The raw exploit-step behavior is compared against all active, non-revoked
        Enterprise ATT&CK techniques stored in Neo4j. BM25 and embedding retrieval
        each contribute up to 20 candidates; FH Genie reranks their deduplicated union
        down to ``limit`` candidates.

        """
        if limit <= 0:
            raise ValueError("ATT&CK candidate limit must be greater than zero")

        behavior = behavior_query(step)

        query = """
        MATCH (technique:AttackTechnique)
        WHERE coalesce(technique.deprecated, false) = false
          AND coalesce(technique.revoked, false) = false
        OPTIONAL MATCH (technique)-[:HAS_TACTIC]->(tactic:AttackTactic)
        WITH technique, collect(DISTINCT {name: tactic.short_name, id: tactic.id}) AS tactics
        RETURN technique.id AS mitre_technique_id, technique.name AS name,
               technique.description AS description, technique.platforms AS platforms,
               technique.procedure_examples AS procedure_examples,
               technique.revoked AS revoked, tactics
        ORDER BY technique.id
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(query)
                records = [dict(record) async for record in result]
        except Exception as exc:
            raise GraphUnavailable("Neo4j ATT&CK candidate query failed") from exc

        if not records:
            raise GraphUnavailable("No active ATT&CK techniques were found in Neo4j")

        if self._embedding_client is None or self._embedding_model is None:
            raise GraphUnavailable("FH Genie embedding retrieval is not configured")
        if self._rerank_client is None or self._rerank_model is None:
            raise GraphUnavailable("FH Genie ATT&CK reranking is not configured")

        try:
            # Cache ATT&CK technique embeddings. They are regenerated only when the
            # searchable ATT&CK text changes.
            async with self._embedding_lock:
                missing: list[tuple[dict[str, Any], list[str]]] = []
                for record in records:
                    technique_id = record["mitre_technique_id"]
                    cache_key = embedding_cache_key(record, self._embedding_model)
                    cached = self._technique_embeddings.get(technique_id)
                    if cached is None or cached[0] != cache_key:
                        missing.append((record, attack_embedding_documents(record)))

                if missing:
                    texts = [text for _, documents in missing for text in documents]
                    vectors = await embed_texts(
                        self._embedding_client,
                        self._embedding_model,
                        texts,
                    )
                    vector_offset = 0
                    for record, documents in missing:
                        record_vectors = vectors[vector_offset : vector_offset + len(documents)]
                        vector_offset += len(documents)
                        self._technique_embeddings[record["mitre_technique_id"]] = (
                            embedding_cache_key(record, self._embedding_model),
                            record_vectors,
                        )

            # Embed the evidence-bounded behavioral abstraction. BM25 continues to
            # use the raw exploit-step behavior below.
            query_vector = (
                await embed_texts(
                    self._embedding_client,
                    self._embedding_model,
                    [behavior],
                )
            )[0]

            vector_scores = vector_similarity_scores(
                query_vector,
                records,
                {
                    technique_id: cached[1]
                    for technique_id, cached in self._technique_embeddings.items()
                },
            )
        except Exception as exc:
            raise GraphUnavailable("FH Genie ATT&CK embedding search failed") from exc

        vector_candidates = top_vector_candidates(records, vector_scores, VECTOR_RETRIEVAL_LIMIT)
        lexical_candidates = top_bm25_candidates(
            records, bm25_scores(behavior, records), BM25_RETRIEVAL_LIMIT
        )
        combined_candidates = combine_candidates(lexical_candidates, vector_candidates)
        rerank_error: Exception | None = None
        try:
            ranked, reranked_metadata = await rerank_candidates(
                self._rerank_client,
                self._rerank_model,
                step,
                combined_candidates[:RERANK_INPUT_LIMIT],
                min(limit, RERANK_LIMIT),
            )
        except Exception as exc:
            rerank_error = exc
            ranked = combined_candidates[: min(limit, RERANK_LIMIT)]
            reranked_metadata = []
            logger.warning(
                "FH Genie ATT&CK reranking failed; using hybrid RRF order",
                extra={
                    "cve_id": cve_id,
                    "step": step.step,
                    "action": step.action,
                    "fallback_candidate_count": len(ranked),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

        log_file = save_retrieval_log(
            cve_id=cve_id,
            step=step,
            query_text=behavior,
            normalized_query_text=behavior,
            bm25_candidates=lexical_candidates,
            vector_candidates=vector_candidates,
            combined_candidates=combined_candidates,
            reranked=reranked_metadata,
            rerank_status=("fallback_rrf" if rerank_error is not None else "completed"),
            rerank_error=str(rerank_error) if rerank_error is not None else None,
        )

        logger.info(
            "ATT&CK hybrid candidate retrieval",
            extra={
                "cve_id": cve_id,
                "step": step.step,
                "action": step.action,
                "behavior_query": behavior,
                "vector_candidate_count": len(vector_candidates),
                "bm25_candidate_count": len(lexical_candidates),
                "combined_candidate_count": len(combined_candidates),
                "reranked_candidate_count": len(ranked),
                "log_file": str(log_file),
            },
        )

        return [
            AttackCandidate(
                mitre_technique_id=record["mitre_technique_id"],
                name=record["name"],
                description=record["description"],
                platforms=record["platforms"],
                procedure_examples=record.get("procedure_examples") or [],
                tactics={
                    item["name"]: item["id"] for item in record["tactics"] if item["id"] is not None
                },
            )
            for record in ranked
        ]

    async def _active_attack_records(self) -> list[dict[str, Any]]:
        query = """
        MATCH (technique:AttackTechnique)
        WHERE coalesce(technique.deprecated, false) = false
          AND coalesce(technique.revoked, false) = false
        OPTIONAL MATCH (technique)-[:HAS_TACTIC]->(tactic:AttackTactic)
        WITH technique, collect(DISTINCT {name: tactic.short_name, id: tactic.id}) AS tactics
        RETURN technique.id AS mitre_technique_id, technique.name AS name,
               technique.description AS description, technique.platforms AS platforms,
               technique.procedure_examples AS procedure_examples, tactics
        ORDER BY technique.id
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(query)
                records = [dict(record) async for record in result]
        except Exception as exc:
            raise GraphUnavailable("Neo4j ATT&CK description retrieval failed") from exc
        if not records:
            raise GraphUnavailable("No active ATT&CK techniques were found in Neo4j")
        return records

    async def description_attack_candidates(
        self, cve_id: str, normalized: Mapping[str, list[str]]
    ) -> dict[str, list[AttackCandidate]]:
        """Retrieve role pools for normalized CTID items using one embedding batch."""
        pools: dict[str, list[AttackCandidate]] = {
            role: [] for role in CTID_NORMALIZED_ROLES.values()
        }
        embedding_items = [
            (role_name, item_index, text)
            for role_name in CTID_NORMALIZED_ROLES
            for item_index, text in enumerate(normalized.get(role_name, []))
        ]
        if not embedding_items:
            return pools
        if self._embedding_client is None or self._embedding_model is None:
            raise GraphUnavailable("FH Genie embedding retrieval is not configured")
        records = await self._active_attack_records()

        if self._embedding_model not in self._description_embedding_cache:
            self._load_description_embedding_cache()
        model_cache = self._description_embedding_cache.get(self._embedding_model, {})
        missing = [
            record["mitre_technique_id"]
            for record in records
            if (
                (cached := model_cache.get(record["mitre_technique_id"])) is None
                or cached[0] != embedding_cache_key(record, self._embedding_model)
            )
        ]
        if missing:
            raise GraphUnavailable(
                "ATT&CK embedding cache is missing or stale for "
                f"{len(missing)} techniques; run the cache initialization command"
            )

        try:
            query_vectors = await embed_texts(
                self._embedding_client,
                self._embedding_model,
                [text for _, _, text in embedding_items],
                batch_size=len(embedding_items),
            )
            aggregate: dict[str, dict[str, dict[str, Any]]] = {
                role: {} for role in CTID_NORMALIZED_ROLES.values()
            }
            embedding_map = []
            for (role_name, item_index, query_text), query_vector in zip(
                embedding_items, query_vectors, strict=True
            ):
                role = CTID_NORMALIZED_ROLES[role_name]
                retrieved_by = f"{role_name}[{item_index}]"
                embedding_map.append(
                    {"role": role, "item_index": item_index, "normalized_text": query_text}
                )
                vector_scores = vector_similarity_scores(
                    query_vector,
                    records,
                    {technique_id: cached[1] for technique_id, cached in model_cache.items()},
                )
                vector_candidates = top_vector_candidates(
                    records, vector_scores, CTID_RETRIEVAL_LIMIT
                )
                lexical_candidates = top_bm25_candidates(
                    records, bm25_scores(query_text, records), CTID_RETRIEVAL_LIMIT
                )
                for rank, candidate in enumerate(vector_candidates, start=1):
                    candidate["vector_rank"] = rank
                for rank, candidate in enumerate(lexical_candidates, start=1):
                    candidate["bm25_rank"] = rank
                merged_candidates = combine_candidates(lexical_candidates, vector_candidates)
                for candidate in merged_candidates:
                    candidate["combined_score"] = candidate.pop("rrf_score")
                    candidate["retrieved_by"] = [retrieved_by]
                    technique_id = candidate["mitre_technique_id"]
                    existing = aggregate[role].get(technique_id)
                    if existing is None:
                        aggregate[role][technique_id] = dict(candidate)
                    else:
                        existing["retrieved_by"] = [
                            *existing.get("retrieved_by", []),
                            retrieved_by,
                        ]
                        for score_name in ("bm25_score", "vector_score", "combined_score"):
                            values = [
                                value
                                for value in (existing.get(score_name), candidate.get(score_name))
                                if value is not None
                            ]
                            existing[score_name] = max(values) if values else None
                        for rank_name in ("bm25_rank", "vector_rank"):
                            ranks = [
                                value
                                for value in (existing.get(rank_name), candidate.get(rank_name))
                                if value is not None
                            ]
                            existing[rank_name] = min(ranks) if ranks else None
                self._save_ctid_retrieval_log(
                    cve_id=cve_id,
                    role=role,
                    item_index=item_index,
                    query_text=query_text,
                    bm25_candidates=lexical_candidates,
                    vector_candidates=vector_candidates,
                    merged_candidates=merged_candidates,
                )
            self._save_ctid_embedding_map(cve_id, embedding_map)
            for role, by_technique in aggregate.items():
                final_candidates = sorted(
                    by_technique.values(),
                    key=lambda item: (
                        -float(item.get("combined_score") or 0.0),
                        item["mitre_technique_id"],
                    ),
                )[:CTID_FINAL_CANDIDATE_LIMIT]
                pools[role] = [self._ctid_attack_candidate(item) for item in final_candidates]
                self._save_ctid_role_pool_log(cve_id, role, final_candidates)
        except GraphUnavailable:
            raise
        except Exception as exc:
            raise GraphUnavailable("FH Genie CTID description embedding search failed") from exc
        return pools

    @staticmethod
    def _ctid_attack_candidate(record: dict[str, Any]) -> AttackCandidate:
        examples = [
            " ".join(str(item).split())[:CTID_PROCEDURE_EXAMPLE_MAX_CHARS]
            for item in (record.get("procedure_examples") or [])[:CTID_PROCEDURE_EXAMPLE_LIMIT]
        ]
        return AttackCandidate(
            mitre_technique_id=record["mitre_technique_id"],
            name=record["name"],
            description=record["description"],
            platforms=record["platforms"],
            procedure_examples=examples,
            retrieved_by=record.get("retrieved_by") or [],
            tactics={
                item["name"]: item["id"] for item in record["tactics"] if item["id"] is not None
            },
            bm25_rank=record.get("bm25_rank"),
            bm25_score=record.get("bm25_score"),
            vector_rank=record.get("vector_rank"),
            vector_score=record.get("vector_score"),
            combined_score=record.get("combined_score"),
        )

    @staticmethod
    def _save_ctid_retrieval_log(
        *,
        cve_id: str,
        role: str,
        item_index: int,
        query_text: str,
        bm25_candidates: list[dict[str, Any]],
        vector_candidates: list[dict[str, Any]],
        merged_candidates: list[dict[str, Any]],
    ) -> Path:
        log_dir = Path("logs") / "fh-genie"
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
        path = log_dir / (f"ctid_retrieval_{cve_id.lower()}_{role}_{item_index}_{timestamp}.json")

        def scored(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [
                {
                    "technique_id": item["mitre_technique_id"],
                    "name": item["name"],
                    "bm25_rank": item.get("bm25_rank"),
                    "bm25_score": item.get("bm25_score"),
                    "vector_rank": item.get("vector_rank"),
                    "vector_score": item.get("vector_score"),
                    "combined_score": item.get("combined_score"),
                }
                for item in items
            ]

        path.write_text(
            json.dumps(
                {
                    "cve_id": cve_id,
                    "role": role,
                    "item_index": item_index,
                    "query_text": query_text,
                    "bm25_candidates": scored(bm25_candidates),
                    "vector_candidates": scored(vector_candidates),
                    "merged_candidates": scored(merged_candidates),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _save_ctid_embedding_map(cve_id: str, items: list[dict[str, object]]) -> Path:
        log_dir = Path("logs") / "fh-genie"
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
        path = log_dir / f"ctid_embedding_map_{cve_id.lower()}_{timestamp}.json"
        path.write_text(
            json.dumps({"cve_id": cve_id, "embedding_items": items}, indent=2),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _save_ctid_role_pool_log(cve_id: str, role: str, candidates: list[dict[str, Any]]) -> Path:
        log_dir = Path("logs") / "fh-genie"
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
        path = log_dir / f"ctid_final_pool_{cve_id.lower()}_{role}_{timestamp}.json"
        path.write_text(
            json.dumps(
                {
                    "cve_id": cve_id,
                    "role": role,
                    "final_candidate_pool": [
                        GraphRepository._ctid_attack_candidate(item).model_dump(mode="json")
                        for item in candidates
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return path
