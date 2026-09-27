import asyncio
import json
import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from neo4j import AsyncDriver

from app.advisory.client import FetchedAdvisory
from app.enrichment.attack_mapper import evidence_id
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
    normalized_behavior_query,
    rerank_candidates,
    save_retrieval_log,
    top_bm25_candidates,
    top_vector_candidates,
    vector_similarity_scores,
)
from app.models import (
    AttackCandidate,
    AttackChainGraph,
    AttackMapping,
    CVELevelAttackMappings,
    CVERecord,
    EvidenceSubgraph,
    ExploitStep,
    GraphEdge,
    GraphNode,
    PresentationEdge,
    PresentationNode,
    PresentationProvenance,
    ValidatedAttackStep,
)
from app.utils.serialization import serialize_neo4j_value

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
        "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT advisory_url IF NOT EXISTS FOR (n:Advisory) REQUIRE n.url IS UNIQUE",
        "CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (n:Evidence) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT step_id IF NOT EXISTS FOR (n:ExploitStep) REQUIRE n.id IS UNIQUE",
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

    async def cached_steps(self, cve_id: str, cache_key: str) -> list[ExploitStep] | None:
        query = """
        MATCH (:CVE {id: $cve_id})-[:HAS_EXPLOIT_STEP]->(step:ExploitStep {cache_key: $cache_key})
        OPTIONAL MATCH (step)-[:SUPPORTED_BY]->(evidence:Evidence)
        WITH step, collect({source_url: evidence.source_url,
                           supporting_text: evidence.supporting_text}) AS evidence
        RETURN step {.step, .action, .prerequisites, .outcome,
                     evidence: evidence} AS step ORDER BY step.step
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(query, cve_id=cve_id, cache_key=cache_key)
                records = [record async for record in result]
        except Exception as exc:
            raise GraphUnavailable("Neo4j cache query failed") from exc
        if not records:
            return None
        # Serialize Neo4j values before creating model instances
        return [
            ExploitStep.model_validate(serialize_neo4j_value(record["step"])) for record in records
        ]

    async def cached_cve(self, cve_id: str, ttl_seconds: int) -> CVERecord | None:
        if ttl_seconds == 0:
            return None
        cutoff = datetime.now(UTC) - timedelta(seconds=ttl_seconds)
        query = """
        MATCH (cve:CVE {id: $cve_id})
        WHERE cve.retrieved_at >= datetime($cutoff) AND cve.record_json IS NOT NULL
        RETURN cve.record_json AS record_json
        """
        try:
            async with self._driver.session() as session:
                record = await (
                    await session.run(query, cve_id=cve_id, cutoff=cutoff.isoformat())
                ).single()
        except Exception as exc:
            raise GraphUnavailable("Neo4j CVE cache query failed") from exc
        if record is None:
            return None
        try:
            return CVERecord.model_validate_json(record["record_json"])
        except ValueError:
            return None

    async def replace_analysis(
        self,
        cve: CVERecord,
        advisories: list[FetchedAdvisory],
        steps: list[ExploitStep],
        *,
        cache_key: str,
        model: str,
        prompt_version: str,
    ) -> None:
        query = """
        MERGE (cve:CVE {id: $cve.cve_id})
        SET cve.description = $cve.description, cve.cvss = $cve.cvss,
            cve.updated_at = $cve.updated_at, cve.record_json = $record_json,
            cve.retrieved_at = datetime($retrieved_at)
        WITH cve
        OPTIONAL MATCH (cve)-[old_context]->()
        WHERE type(old_context) IN
          ['AFFECTS', 'REFERENCES']
        DELETE old_context
        WITH DISTINCT cve
        OPTIONAL MATCH (cve)-[:HAS_EXPLOIT_STEP]->(old:ExploitStep)
        DETACH DELETE old
        WITH DISTINCT cve
        FOREACH (product IN $products |
          MERGE (p:Product {key: product.key})
          SET p.id = product.key, p.vendor = product.vendor, p.name = product.product,
              p.versions = product.versions
          MERGE (cve)-[:AFFECTS]->(p)
          FOREACH (platform IN product.platforms |
            MERGE (pl:Platform {name: platform}) SET pl.id = platform
            MERGE (p)-[:RUNS_ON]->(pl))
          FOREACH (_ IN CASE WHEN product.component IS NULL THEN [] ELSE [1] END |
            MERGE (component:Component {name: product.component})
            SET component.id = product.component
            MERGE (p)-[:HAS_COMPONENT]->(component)))
        FOREACH (advisory IN $advisories |
          MERGE (a:Advisory {url: advisory.url})
          SET a.id = advisory.url, a.tags = advisory.tags,
              a.selection_reason = advisory.selection_reason,
              a.retrieved_at = advisory.retrieved_at, a.checksum = advisory.checksum
          MERGE (cve)-[:REFERENCES]->(a))
        WITH cve
        UNWIND CASE WHEN size($steps) = 0 THEN [null] ELSE $steps END AS item
        FOREACH (_ IN CASE WHEN item IS NULL THEN [] ELSE [1] END |
          MERGE (step:ExploitStep {id: item.id})
          SET step.step = item.step, step.action = item.action,
              step.prerequisites = item.prerequisites, step.outcome = item.outcome,
              step.cache_key = $cache_key, step.model = $model,
              step.prompt_version = $prompt_version
          MERGE (cve)-[:HAS_EXPLOIT_STEP]->(step)
          FOREACH (ev IN item.evidence |
            MERGE (e:Evidence {id: ev.id})
            SET e.source_url = ev.source_url, e.supporting_text = ev.supporting_text
            MERGE (step)-[:SUPPORTED_BY]->(e)
            MERGE (a:Advisory {url: ev.source_url})
            SET a.id = ev.source_url
            MERGE (a)-[:CONTAINS]->(e)))
        WITH DISTINCT cve
        MATCH (cve)-[:HAS_EXPLOIT_STEP]->(left:ExploitStep)
        MATCH (cve)-[:HAS_EXPLOIT_STEP]->(right:ExploitStep)
        WHERE right.step = left.step + 1
        MERGE (left)-[:NEXT]->(right)
        """
        products = [
            {
                "key": "|".join(filter(None, [item.vendor, item.product])) or cve.cve_id,
                "vendor": item.vendor,
                "product": item.product,
                "versions": item.versions,
                "platforms": item.platforms,
                "component": item.vulnerable_component,
            }
            for item in cve.affected_products
        ]
        advisory_data = [
            {
                "url": str(item.selected.reference.url),
                "tags": item.selected.reference.tags,
                "selection_reason": item.selected.reason.value,
                "retrieved_at": item.retrieved_at.isoformat(),
                "checksum": item.checksum,
            }
            for item in advisories
        ]
        step_data = []
        for step in steps:
            step_id = f"{cve.cve_id}:{step.step}"
            data = step.model_dump(mode="json")
            data["id"] = step_id
            data["evidence"] = [
                {
                    **evidence,
                    "id": evidence_id(evidence["source_url"], evidence["supporting_text"]),
                }
                for evidence in data["evidence"]
            ]
            step_data.append(data)
        cve_data = cve.model_dump(mode="json")
        cve_data["cvss"] = cve.cvss.model_dump_json() if cve.cvss else None
        try:
            async with self._driver.session() as session:
                await (
                    await session.run(
                        query,
                        cve=cve_data,
                        record_json=cve.model_dump_json(),
                        retrieved_at=max(
                            (source.retrieved_at for source in cve.sources),
                            default=datetime.now(UTC),
                        ).isoformat(),
                        products=products,
                        advisories=advisory_data,
                        steps=step_data,
                        cache_key=cache_key,
                        model=model,
                        prompt_version=prompt_version,
                    )
                ).consume()
        except Exception as exc:
            raise GraphUnavailable("Neo4j analysis update failed") from exc

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

        normalized_behavior: str | None = None
        normalization_error: Exception | None = None
        for attempt in range(2):
            try:
                normalized_behavior = await normalized_behavior_query(
                    self._rerank_client, self._rerank_model, step
                )
                break
            except Exception as exc:
                normalization_error = exc
                logger.warning(
                    "FH Genie behavioral query normalization attempt failed",
                    extra={"cve_id": cve_id, "step": step.step, "attempt": attempt + 1},
                )
        if normalized_behavior is None:
            normalized_behavior = behavior
            logger.warning(
                "FH Genie behavioral query normalization failed; using raw behavior query",
                extra={
                    "cve_id": cve_id,
                    "step": step.step,
                    "normalization_error": str(normalization_error),
                    "raw_behavior_query": behavior,
                },
            )

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
                    [normalized_behavior],
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
            normalized_query_text=normalized_behavior,
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
                "normalized_behavior_query": normalized_behavior,
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
            for item in (record.get("procedure_examples") or [])[
                :CTID_PROCEDURE_EXAMPLE_LIMIT
            ]
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
        path = log_dir / (
            f"ctid_retrieval_{cve_id.lower()}_{role}_{item_index}_{timestamp}.json"
        )

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
    def _save_ctid_role_pool_log(
        cve_id: str, role: str, candidates: list[dict[str, Any]]
    ) -> Path:
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

    async def replace_attack_mappings(
        self,
        cve_id: str,
        mappings: list[AttackMapping],
        *,
        model: str,
        prompt_version: str,
    ) -> None:
        query = """
        MATCH (cve:CVE {id: $cve_id})-[:HAS_EXPLOIT_STEP]->(step:ExploitStep)
        OPTIONAL MATCH (step)-[old:MAPS_TO]->(:AttackTechnique)
        DELETE old
        WITH DISTINCT cve
        UNWIND $mappings AS mapping
        MATCH (cve)-[:HAS_EXPLOIT_STEP]->(step:ExploitStep {step: mapping.step})
        OPTIONAL MATCH (technique:AttackTechnique {id: mapping.mitre_technique_id})
        FOREACH (_ IN CASE WHEN technique IS NULL THEN [] ELSE [1] END |
          MERGE (step)-[edge:MAPS_TO]->(technique)
          SET edge.reasoning = mapping.reasoning, edge.confidence = mapping.confidence,
              edge.model = $model, edge.prompt_version = $prompt_version,
              edge.tactic_id = mapping.mitre_tactic_id,
              edge.evidence_ids = mapping.evidence_ids)
        """
        try:
            async with self._driver.session() as session:
                await (
                    await session.run(
                        query,
                        cve_id=cve_id,
                        mappings=[item.model_dump(mode="json") for item in mappings],
                        model=model,
                        prompt_version=prompt_version,
                    )
                ).consume()
        except Exception as exc:
            raise GraphUnavailable("Neo4j ATT&CK mapping update failed") from exc

    async def replace_cve_level_attack_mappings(
        self,
        cve_id: str,
        mappings: CVELevelAttackMappings,
        *,
        model: str,
        prompt_version: str,
    ) -> None:
        """Replace the additive CTID CVE-level mapping nodes and relationships."""
        query = """
        MATCH (cve:CVE {id: $cve_id})
        OPTIONAL MATCH (cve)-[:HAS_CVE_ATTACK_MAPPING]->(old:CVEAttackMapping)
        DETACH DELETE old
        WITH cve
        UNWIND $mappings AS item
        CREATE (mapping:CVEAttackMapping {
          id: $cve_id + ':' + item.id,
          mapping_id: item.id,
          category: item.category,
          action: item.action,
          reasoning: item.reasoning,
          confidence: item.confidence,
          tactic_id: item.mitre_tactic_id,
          evidence_ids: item.evidence_ids,
          validation_status: item.validation.status,
          processing_status: item.processing_status,
          enabled_by: item.enabled_by,
          model: $model,
          prompt_version: $prompt_version
        })
        MERGE (cve)-[:HAS_CVE_ATTACK_MAPPING]->(mapping)
        WITH mapping, item
        OPTIONAL MATCH (technique:AttackTechnique {id: item.mitre_technique_id})
        FOREACH (_ IN CASE WHEN technique IS NULL THEN [] ELSE [1] END |
          MERGE (mapping)-[:MAPS_TO]->(technique))
        WITH mapping, item
        UNWIND CASE WHEN item.evidence_ids = [] THEN [null]
                    ELSE item.evidence_ids END AS evidence_id
        OPTIONAL MATCH (evidence:Evidence {id: evidence_id})
        FOREACH (_ IN CASE WHEN evidence IS NULL THEN [] ELSE [1] END |
          MERGE (mapping)-[:SUPPORTED_BY]->(evidence))
        """
        try:
            async with self._driver.session() as session:
                await (
                    await session.run(
                        query,
                        cve_id=cve_id,
                        mappings=[
                            {**item.model_dump(mode="json"), "category": category}
                            for category, items in (
                                ("exploitation_technique", mappings.exploitation_techniques),
                                ("primary_impact", mappings.primary_impacts),
                                ("secondary_impact", mappings.secondary_impacts),
                            )
                            for item in items
                        ],
                        model=model,
                        prompt_version=prompt_version,
                    )
                ).consume()
                await (
                    await session.run(
                        """
                        MATCH (:CVE {id: $cve_id})-[:HAS_CVE_ATTACK_MAPPING]->
                              (secondary:CVEAttackMapping)
                        UNWIND secondary.enabled_by AS primary_id
                        MATCH (:CVE {id: $cve_id})-[:HAS_CVE_ATTACK_MAPPING]->
                              (primary:CVEAttackMapping {mapping_id: primary_id})
                        MERGE (secondary)-[:ENABLED_BY]->(primary)
                        """,
                        cve_id=cve_id,
                    )
                ).consume()
        except Exception as exc:
            raise GraphUnavailable("Neo4j CVE-level ATT&CK mapping update failed") from exc

    async def official_attack_context(self, technique_ids: list[str]) -> dict[str, AttackCandidate]:
        if not technique_ids:
            return {}
        query = """
        MATCH (technique:AttackTechnique)
        WHERE technique.id IN $technique_ids
          AND technique.revoked = false AND technique.deprecated = false
        OPTIONAL MATCH (technique)-[:HAS_TACTIC]->(tactic:AttackTactic)
        WITH technique, collect(DISTINCT {name: tactic.short_name, id: tactic.id}) AS tactics
        RETURN technique.id AS mitre_technique_id, technique.name AS name,
               technique.description AS description, technique.platforms AS platforms,
               technique.procedure_examples AS procedure_examples,
               tactics ORDER BY technique.id
        """
        try:
            async with self._driver.session() as session:
                result = await session.run(query, technique_ids=sorted(set(technique_ids)))
                records = [record async for record in result]
        except Exception as exc:
            raise GraphUnavailable("Neo4j ATT&CK validation query failed") from exc
        candidates = [
            AttackCandidate(
                mitre_technique_id=record["mitre_technique_id"],
                name=record["name"],
                description=record["description"],
                platforms=record["platforms"],
                procedure_examples=record["procedure_examples"] or [],
                tactics={
                    item["name"]: item["id"] for item in record["tactics"] if item["id"] is not None
                },
            )
            for record in records
        ]
        return {item.mitre_technique_id: item for item in candidates}

    async def validation_facts(
        self,
        cve_id: str,
        mappings: list[AttackMapping],
        cve_platforms: list[str],
    ) -> dict[int, dict[str, Any]]:
        query = """
        UNWIND $mappings AS mapping
        OPTIONAL MATCH (technique:AttackTechnique {id: mapping.mitre_technique_id})
        OPTIONAL MATCH (technique)-[:HAS_TACTIC]->
                       (tactic:AttackTactic {id: mapping.mitre_tactic_id})
        OPTIONAL MATCH (:CVE {id: $cve_id})-[:HAS_EXPLOIT_STEP]->
                       (step:ExploitStep {step: mapping.step})
        OPTIONAL MATCH (step)-[:SUPPORTED_BY]->(linked:Evidence)
        WHERE linked.id IN mapping.evidence_ids
        OPTIONAL MATCH (node:Evidence)
        WHERE node.id IN mapping.evidence_ids
        WITH mapping, technique, tactic,
             collect(DISTINCT linked.id) AS linked_ids,
             collect(DISTINCT node.id) AS node_ids,
             collect(DISTINCT CASE WHEN node.supporting_text IS NULL OR
               trim(node.supporting_text) = '' THEN node.id ELSE null END) AS empty_text_ids
        RETURN mapping.step AS step,
               technique IS NOT NULL AS technique_lookup_found,
               technique.name AS technique_name,
               technique.platforms AS technique_platforms,
               tactic IS NOT NULL AS tactic_relationship_found,
               linked_ids, node_ids, empty_text_ids
        ORDER BY step
        """
        parameters: dict[str, Any] = {
            "cve_id": cve_id,
            "cve_platforms": cve_platforms,
            "mappings": [item.model_dump(mode="json") for item in mappings],
        }
        try:
            async with self._driver.session() as session:
                result = await session.run(query, **parameters)
                records = [record async for record in result]
        except Exception as exc:
            raise GraphUnavailable("Neo4j validator diagnostics query failed") from exc

        facts: dict[int, dict[str, Any]] = {}
        mapping_by_step = {item.step: item for item in mappings}
        for record in records:
            step = record["step"]
            mapping = mapping_by_step[step]
            expected = set(mapping.evidence_ids)
            linked = set(record["linked_ids"])
            nodes = set(record["node_ids"])
            empty = set(record["empty_text_ids"])
            facts[step] = {
                "technique_lookup_found": record["technique_lookup_found"],
                "technique_name": record["technique_name"],
                "technique_platforms": record["technique_platforms"] or [],
                "cve_platforms": cve_platforms,
                "tactic_relationship_found": record["tactic_relationship_found"],
                "evidence_ids_found": expected == linked and not empty,
                "missing_evidence_nodes": sorted(expected - nodes),
                "wrong_evidence_relationship": sorted((expected & nodes) - linked),
                "empty_evidence_text": sorted(empty),
            }
        return facts

    async def replace_validated_attack_chain(
        self,
        cve_id: str,
        chain: list[ValidatedAttackStep],
        *,
        mapping_model: str,
        mapping_prompt_version: str,
        validation_model: str,
        validation_prompt_version: str,
    ) -> None:
        query = """
        MATCH (cve:CVE {id: $cve_id})-[:HAS_EXPLOIT_STEP]->(step:ExploitStep)
        OPTIONAL MATCH (step)-[old:MAPS_TO]->(:AttackTechnique)
        DELETE old
        WITH DISTINCT cve
        UNWIND $chain AS item
        MATCH (cve)-[:HAS_EXPLOIT_STEP]->(step:ExploitStep {step: item.step})
        OPTIONAL MATCH (technique:AttackTechnique {id: item.proposed_technique_id})
        FOREACH (_ IN CASE WHEN technique IS NULL OR item.validation.status <> 'validated'
                           THEN [] ELSE [1] END |
          MERGE (step)-[edge:MAPS_TO]->(technique)
          SET edge.reasoning = item.validation.reasoning,
              edge.confidence = item.validation.validator_confidence,
              edge.model = $mapping_model,
              edge.prompt_version = $mapping_prompt_version,
              edge.tactic_id = item.mitre_tactic_id,
              edge.evidence_ids = item.evidence_ids,
              edge.validation_status = item.validation.status,
              edge.validation_model = $validation_model,
              edge.validation_prompt_version = $validation_prompt_version)
        """
        try:
            async with self._driver.session() as session:
                await (
                    await session.run(
                        query,
                        cve_id=cve_id,
                        chain=[item.model_dump(mode="json") for item in chain],
                        mapping_model=mapping_model,
                        mapping_prompt_version=mapping_prompt_version,
                        validation_model=validation_model,
                        validation_prompt_version=validation_prompt_version,
                    )
                ).consume()
        except Exception as exc:
            raise GraphUnavailable("Neo4j validated attack-chain update failed") from exc

    async def validated_attack_chain_graph(self, cve_id: str) -> AttackChainGraph | None:
        context_query = """
        MATCH (cve:CVE {id: $cve_id})
        RETURN cve.description AS description
        """
        steps_query = """
        MATCH (:CVE {id: $cve_id})-[:HAS_EXPLOIT_STEP]->(step:ExploitStep)
        OPTIONAL MATCH (step)-[:SUPPORTED_BY]->(evidence:Evidence)
        WITH step, collect(DISTINCT {id: evidence.id, source_url: evidence.source_url,
             supporting_text: evidence.supporting_text}) AS evidence
        OPTIONAL MATCH (step)-[mapping:MAPS_TO]->(technique:AttackTechnique)
        OPTIONAL MATCH (technique)-[:HAS_TACTIC]->(tactic:AttackTactic)
        WHERE tactic.id = mapping.tactic_id OR tactic IS NULL
        RETURN step.id AS id, step.step AS step, step.action AS action,
               step.prerequisites AS prerequisites, step.outcome AS outcome, evidence,
               technique.id AS technique_id, technique.name AS technique_name,
               tactic.id AS tactic_id, tactic.name AS tactic_name,
               mapping.reasoning AS reasoning, mapping.confidence AS confidence,
               mapping.evidence_ids AS evidence_ids,
               mapping.validation_status AS validation_status
        ORDER BY step.step
        """
        try:
            async with self._driver.session() as session:
                context = await (await session.run(context_query, cve_id=cve_id)).single()
                if context is None:
                    return None
                result = await session.run(steps_query, cve_id=cve_id)
                steps = [record async for record in result]
        except Exception as exc:
            raise GraphUnavailable("Neo4j attack-chain graph query failed") from exc
        return self._presentation_graph(cve_id, context, steps)

    @staticmethod
    def _presentation_graph(
        cve_id: str, context: Mapping[str, Any], steps: Sequence[Mapping[str, Any]]
    ) -> AttackChainGraph:
        nodes = [
            PresentationNode(
                id=cve_id,
                type="cve",
                label=cve_id,
                provenance=PresentationProvenance.AUTHORITATIVE,
                properties={"description": context["description"]},
            )
        ]
        edges: list[PresentationEdge] = []
        previous_step: str | None = None
        technique_nodes: set[str] = set()
        tactic_nodes: set[str] = set()
        for record in steps:
            step_id = record["id"]
            evidence = [item for item in record["evidence"] if item["id"]]
            validation_status = record["validation_status"] or "unmapped"
            # Serialize Neo4j values in properties dict
            properties: dict[str, object] = {
                "step": record["step"],
                "action": record["action"],
                "prerequisites": record["prerequisites"] or [],
                "outcome": record["outcome"],
                "mitre_technique_id": record["technique_id"],
                "mitre_tactic_id": record["tactic_id"],
                "reasoning": record["reasoning"] or "No validated ATT&CK mapping.",
                "confidence": serialize_neo4j_value(record["confidence"]) or 0.0,
                "evidence_ids": record["evidence_ids"] or [],
                "evidence_sources": sorted(
                    {serialize_neo4j_value(item["source_url"]) for item in evidence}
                ),
                "evidence": [serialize_neo4j_value(item) for item in evidence],
                "validation_status": validation_status,
            }
            nodes.append(
                PresentationNode(
                    id=step_id,
                    type="exploit_step",
                    label=f"Step {record['step']}: {record['action']}",
                    provenance=PresentationProvenance.ADVISORY_DERIVED,
                    properties=properties,
                )
            )
            if previous_step:
                edges.append(
                    PresentationEdge(
                        source=previous_step,
                        target=step_id,
                        relationship="NEXT",
                        provenance=PresentationProvenance.ADVISORY_DERIVED,
                    )
                )
            else:
                edges.append(
                    PresentationEdge(
                        source=cve_id,
                        target=step_id,
                        relationship="HAS_EXPLOIT_STEP",
                        provenance=PresentationProvenance.ADVISORY_DERIVED,
                    )
                )
            previous_step = step_id
            technique_id = record["technique_id"]
            tactic_id = record["tactic_id"]
            if technique_id:
                if technique_id not in technique_nodes:
                    nodes.append(
                        PresentationNode(
                            id=technique_id,
                            type="attack_technique",
                            label=f"{technique_id}: {record['technique_name']}",
                            provenance=PresentationProvenance.AUTHORITATIVE,
                        )
                    )
                    technique_nodes.add(technique_id)
                edges.append(
                    PresentationEdge(
                        source=step_id,
                        target=technique_id,
                        relationship="MAPS_TO",
                        provenance=PresentationProvenance.LLM_INFERRED,
                        properties={
                            "reasoning": properties["reasoning"],
                            "confidence": properties["confidence"],
                            "validation_status": validation_status,
                        },
                    )
                )
            if technique_id and tactic_id:
                if tactic_id not in tactic_nodes:
                    nodes.append(
                        PresentationNode(
                            id=tactic_id,
                            type="attack_tactic",
                            label=f"{tactic_id}: {record['tactic_name']}",
                            provenance=PresentationProvenance.AUTHORITATIVE,
                        )
                    )
                    tactic_nodes.add(tactic_id)
                edges.append(
                    PresentationEdge(
                        source=technique_id,
                        target=tactic_id,
                        relationship="HAS_TACTIC",
                        provenance=PresentationProvenance.AUTHORITATIVE,
                    )
                )
        return AttackChainGraph(cve_id=cve_id, nodes=nodes, edges=edges)

    async def subgraph(self, cve_id: str) -> EvidenceSubgraph:
        query = """
        MATCH path=(cve:CVE {id: $cve_id})-[*0..3]->(node)
        WHERE all(rel IN relationships(path) WHERE type(rel) IN
          ['AFFECTS','RUNS_ON','HAS_COMPONENT','REFERENCES','CONTAINS','HAS_EXPLOIT_STEP',
           'SUPPORTED_BY','NEXT','MAPS_TO','HAS_TACTIC',
           'HAS_CVE_ATTACK_MAPPING','ENABLED_BY'])
        UNWIND nodes(path) AS n
        WITH collect(DISTINCT n) AS nodes, collect(DISTINCT relationships(path)) AS paths
        UNWIND paths AS rels UNWIND rels AS rel
        RETURN nodes,
          collect(DISTINCT {source: startNode(rel).id, relationship: type(rel),
                            target: endNode(rel).id,
                            authoritative: CASE WHEN type(rel) = 'MAPS_TO' THEN false
                                                ELSE coalesce(rel.authoritative, true)
                                           END}) AS edges
        """
        record = None
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                async with self._driver.session() as session:
                    record = await (await session.run(query, cve_id=cve_id)).single()
                last_error = None
                break
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Neo4j subgraph query attempt failed",
                    exc_info=True,
                    extra={"cve_id": cve_id, "attempt": attempt + 1},
                )
        if last_error is not None:
            raise GraphUnavailable(
                f"Neo4j subgraph query failed after 2 attempts: {last_error}"
            ) from last_error
        if record is None:
            return EvidenceSubgraph()
        nodes = []
        for node in record["nodes"]:
            properties = dict(node)
            node_id = str(properties.pop("id", properties.get("url", properties.get("key", ""))))
            labels = sorted(node.labels)
            # Serialize Neo4j temporal types before creating GraphNode
            properties = serialize_neo4j_value(properties)
            nodes.append(GraphNode(id=node_id, type=labels[0].lower(), properties=properties))
        edges = [GraphEdge(**edge) for edge in record["edges"] if edge["source"] and edge["target"]]
        return EvidenceSubgraph(
            nodes=sorted(nodes, key=lambda item: (item.type, item.id)),
            edges=sorted(edges, key=lambda item: (item.source, item.relationship, item.target)),
        )
