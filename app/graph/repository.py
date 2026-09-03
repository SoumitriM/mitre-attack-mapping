import asyncio
import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from neo4j import AsyncDriver

from app.advisory.client import FetchedAdvisory
from app.enrichment.attack_mapper import evidence_id
from app.enrichment.candidate_retrieval import (
    RERANK_LIMIT,
    VECTOR_RETRIEVAL_LIMIT,
    EmbeddingClient,
    RerankClient,
    behavior_query,
    canonical_attack_document,
    embed_texts,
    embedding_cache_key,
    rerank_candidates,
    save_retrieval_log,
    top_vector_candidates,
    vector_similarity_scores,
)
from app.models import (
    AttackCandidate,
    AttackChainGraph,
    AttackMapping,
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


class GraphUnavailable(RuntimeError):
    pass


class TaxonomyUnavailable(GraphUnavailable):
    pass


class GraphRepository:
    CONSTRAINTS = (
        "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (n:CAPEC) REQUIRE n.id IS UNIQUE",
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
    ) -> None:
        self._driver = driver
        self._embedding_client = embedding_client
        self._embedding_model = embedding_model
        self._rerank_client = rerank_client or cast(RerankClient | None, embedding_client)
        self._rerank_model = rerank_model or embedding_model
        self._technique_embeddings: dict[str, tuple[str, list[float]]] = {}
        self._embedding_lock = asyncio.Lock()

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
                        "MATCH (r:DatasetRelease) WHERE r.name IN ['CWE', 'CAPEC', 'ATT&CK'] "
                        "RETURN collect(DISTINCT r.name) AS names"
                    )
                ).single()
            if record is None or set(record["names"]) != {"CWE", "CAPEC", "ATT&CK"}:
                raise TaxonomyUnavailable("required CWE/CAPEC/ATT&CK datasets are not loaded")
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
          ['HAS_WEAKNESS', 'HAS_ATTACK_PATTERN', 'AFFECTS', 'REFERENCES']
        DELETE old_context
        WITH DISTINCT cve
        OPTIONAL MATCH (cve)-[:HAS_EXPLOIT_STEP]->(old:ExploitStep)
        DETACH DELETE old
        WITH DISTINCT cve
        FOREACH (cwe_id IN $cve.cwe_ids |
          MERGE (cwe:CWE {id: cwe_id}) MERGE (cve)-[:HAS_WEAKNESS]->(cwe))
        FOREACH (capec_id IN $cve.capec_ids |
          MERGE (capec:CAPEC {id: capec_id}) MERGE (cve)-[:HAS_ATTACK_PATTERN]->(capec))
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
        platforms: list[str],
        cve_id: str | None = None,
        cwe_ids: list[str] | None = None,
        capec_ids: list[str] | None = None,
        cve_description: str | None = None,
        *,
        limit: int = 10,
    ) -> list[AttackCandidate]:
        """Retrieve ATT&CK candidates using semantic vector similarity only.

        The raw exploit-step behavior is embedded and compared against all active,
        non-revoked Enterprise ATT&CK techniques stored in Neo4j. The top ``limit``
        candidates are returned to FH Genie, which decides on one technique+tactic
        or returns an unmapped result.

        ``platforms``, ``cwe_ids``, ``capec_ids``, and ``cve_description`` are kept
        in the signature for compatibility with existing callers, but they do not
        influence candidate ranking.
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
                missing: list[tuple[dict[str, Any], str]] = []
                for record in records:
                    technique_id = record["mitre_technique_id"]
                    attack_text = canonical_attack_document(record)
                    cache_key = embedding_cache_key(record, self._embedding_model)
                    cached = self._technique_embeddings.get(technique_id)
                    if cached is None or cached[0] != cache_key:
                        missing.append((record, attack_text))

                if missing:
                    texts = [text for _, text in missing]
                    vectors = await embed_texts(
                        self._embedding_client,
                        self._embedding_model,
                        texts,
                    )
                    for (record, _), vector in zip(missing, vectors, strict=True):
                        self._technique_embeddings[record["mitre_technique_id"]] = (
                            embedding_cache_key(record, self._embedding_model),
                            vector,
                        )

            # Embed the raw exploit-step behavior only. No inferred tactics,
            # platform boosts, taxonomy keywords, aliases, or hand-written concepts.
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

        vector_candidates = top_vector_candidates(
            records, vector_scores, VECTOR_RETRIEVAL_LIMIT
        )
        rerank_error: Exception | None = None
        for attempt in range(2):
            try:
                ranked, reranked_metadata = await rerank_candidates(
                    self._rerank_client,
                    self._rerank_model,
                    step,
                    vector_candidates,
                    min(limit, RERANK_LIMIT),
                )
                break
            except Exception as exc:
                rerank_error = exc
                logger.warning(
                    "FH Genie ATT&CK reranking attempt failed",
                    extra={
                        "cve_id": cve_id,
                        "step": step.step,
                        "action": step.action,
                        "attempt": attempt + 1,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
        else:
            raise GraphUnavailable(
                f"FH Genie ATT&CK reranking failed for step {step.step}: {rerank_error}"
            ) from rerank_error

        log_file = save_retrieval_log(
            cve_id=cve_id,
            step=step,
            query_text=behavior,
            vector_candidates=vector_candidates,
            reranked=reranked_metadata,
        )

        logger.info(
            "ATT&CK vector candidate retrieval",
            extra={
                "cve_id": cve_id,
                "step": step.step,
                "action": step.action,
                "behavior_query": behavior,
                "vector_candidate_count": len(vector_candidates),
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
                tactics={
                    item["name"]: item["id"]
                    for item in record["tactics"]
                    if item["id"] is not None
                },
            )
            for record in ranked
        ]

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
        OPTIONAL MATCH (cve)-[:HAS_WEAKNESS]->(cwe:CWE)
        OPTIONAL MATCH (cwe)-[:RELATED_TO_CAPEC]->(capec:CAPEC)
        RETURN cve.description AS description,
               collect(DISTINCT {id: cwe.id, name: cwe.name}) AS cwes,
               collect(DISTINCT {id: capec.id, name: capec.name}) AS capecs
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
        cwes = [item for item in context["cwes"] if item["id"] is not None]
        capecs = [item for item in context["capecs"] if item["id"] is not None]
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
        for cwe in sorted(cwes, key=lambda item: item["id"]):
            nodes.append(
                PresentationNode(
                    id=cwe["id"],
                    type="cwe",
                    label=cwe["id"],
                    provenance=PresentationProvenance.AUTHORITATIVE,
                    properties={"name": cwe["name"]},
                )
            )
            edges.append(
                PresentationEdge(
                    source=cve_id,
                    target=cwe["id"],
                    relationship="HAS_WEAKNESS",
                    provenance=PresentationProvenance.AUTHORITATIVE,
                )
            )
        for capec in sorted(capecs, key=lambda item: item["id"]):
            nodes.append(
                PresentationNode(
                    id=capec["id"],
                    type="capec",
                    label=capec["id"],
                    provenance=PresentationProvenance.AUTHORITATIVE,
                    properties={"name": capec["name"]},
                )
            )
            for cwe in cwes:
                edges.append(
                    PresentationEdge(
                        source=cwe["id"],
                        target=capec["id"],
                        relationship="RELATED_TO_CAPEC",
                        provenance=PresentationProvenance.AUTHORITATIVE,
                    )
                )
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
            elif capecs:
                for capec in capecs:
                    edges.append(
                        PresentationEdge(
                            source=capec["id"],
                            target=step_id,
                            relationship="CONTEXTUALIZES",
                            provenance=PresentationProvenance.ADVISORY_DERIVED,
                            properties={"presentation_only": True},
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
        MATCH path=(cve:CVE {id: $cve_id})-[*0..3]-(node)
        WHERE all(rel IN relationships(path) WHERE type(rel) IN
          ['HAS_WEAKNESS','RELATED_TO_CAPEC','HAS_ATTACK_PATTERN','AFFECTS',
           'RUNS_ON','HAS_COMPONENT','REFERENCES','CONTAINS','HAS_EXPLOIT_STEP',
           'SUPPORTED_BY','NEXT','MAPS_TO','HAS_TACTIC'])
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
        try:
            async with self._driver.session() as session:
                record = await (await session.run(query, cve_id=cve_id)).single()
        except Exception as exc:
            raise GraphUnavailable("Neo4j subgraph query failed") from exc
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
