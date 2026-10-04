import asyncio
import json
import logging
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

    async def attack_names(self, ids: list[str]) -> dict[str, str]:
        """Resolve display names by existing IDs without selecting or validating mappings."""
        if not ids:
            return {}
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    "MATCH (n) WHERE (n:AttackTechnique OR n:AttackTactic) "
                    "AND n.id IN $ids RETURN n.id AS id, n.name AS name",
                    ids=ids,
                )
                return {row["id"]: row["name"] for row in await result.data()}
        except Exception as exc:
            raise GraphUnavailable("ATT&CK display-name lookup failed") from exc

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
