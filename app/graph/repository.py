from datetime import UTC, datetime, timedelta

from neo4j import AsyncDriver

from app.advisory.client import FetchedAdvisory
from app.enrichment.attack_mapper import evidence_id
from app.models import (
    AttackCandidate,
    AttackMapping,
    CVERecord,
    EvidenceSubgraph,
    ExploitStep,
    GraphEdge,
    GraphNode,
    ValidatedAttackStep,
)


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

    def __init__(self, driver: AsyncDriver) -> None:
        self._driver = driver

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
                record = await (await session.run(
                    "MATCH (r:DatasetRelease) WHERE r.name IN ['CWE', 'CAPEC', 'ATT&CK'] "
                    "RETURN collect(DISTINCT r.name) AS names"
                )).single()
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
        return [ExploitStep.model_validate(record["step"]) for record in records]

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
                record = await (await session.run(
                    query, cve_id=cve_id, cutoff=cutoff.isoformat()
                )).single()
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
                await (await session.run(
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
                )).consume()
        except Exception as exc:
            raise GraphUnavailable("Neo4j analysis update failed") from exc

    async def attack_candidates(
        self,
        step: ExploitStep,
        platforms: list[str],
        *,
        limit: int = 8,
    ) -> list[AttackCandidate]:
        query = """
        MATCH (technique:AttackTechnique)-[:HAS_TACTIC]->(tactic:AttackTactic)
        WHERE technique.revoked = false AND technique.deprecated = false
          AND (size($platforms) = 0 OR any(platform IN technique.platforms
              WHERE toLower(platform) IN $platforms))
        WITH technique, collect(DISTINCT {name: tactic.short_name, id: tactic.id}) AS tactics,
             size([token IN $tokens WHERE
               toLower(technique.name) CONTAINS token OR
               toLower(technique.description) CONTAINS token]) AS score
        WHERE score > 0
        RETURN technique.id AS mitre_technique_id, technique.name AS name,
               technique.description AS description, technique.platforms AS platforms,
               tactics, score
        ORDER BY score DESC, technique.id
        LIMIT $limit
        """
        text = " ".join(
            [
                step.action,
                *step.prerequisites,
                step.outcome,
                *(item.supporting_text for item in step.evidence),
            ]
        ).lower()
        stop = {"that", "this", "with", "from", "into", "then", "when", "where", "every"}
        tokens = list(
            dict.fromkeys(
                token.strip(".,:;()[]{}'\"")
                for token in text.split()
                if len(token.strip(".,:;()[]{}'\"")) >= 4
                and token.strip(".,:;()[]{}'\"") not in stop
            )
        )[:40]
        try:
            async with self._driver.session() as session:
                result = await session.run(
                    query,
                    platforms=sorted({item.lower() for item in platforms}),
                    tokens=tokens,
                    limit=limit,
                )
                records = [record async for record in result]
        except Exception as exc:
            raise GraphUnavailable("Neo4j ATT&CK candidate query failed") from exc
        return [
            AttackCandidate(
                mitre_technique_id=record["mitre_technique_id"],
                name=record["name"],
                description=record["description"],
                platforms=record["platforms"],
                tactics={item["name"]: item["id"] for item in record["tactics"]},
            )
            for record in records
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
                await (await session.run(
                    query,
                    cve_id=cve_id,
                    mappings=[item.model_dump(mode="json") for item in mappings],
                    model=model,
                    prompt_version=prompt_version,
                )).consume()
        except Exception as exc:
            raise GraphUnavailable("Neo4j ATT&CK mapping update failed") from exc

    async def official_attack_context(
        self, technique_ids: list[str]
    ) -> dict[str, AttackCandidate]:
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
                result = await session.run(
                    query, technique_ids=sorted(set(technique_ids))
                )
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
                    item["name"]: item["id"]
                    for item in record["tactics"]
                    if item["id"] is not None
                },
            )
            for record in records
        ]
        return {item.mitre_technique_id: item for item in candidates}

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
        OPTIONAL MATCH (technique:AttackTechnique {id: item.mitre_technique_id})
        FOREACH (_ IN CASE WHEN technique IS NULL OR item.validation_status <> 'validated'
                           THEN [] ELSE [1] END |
          MERGE (step)-[edge:MAPS_TO]->(technique)
          SET edge.reasoning = item.reasoning, edge.confidence = item.confidence,
              edge.model = $mapping_model,
              edge.prompt_version = $mapping_prompt_version,
              edge.tactic_id = item.mitre_tactic_id,
              edge.evidence_ids = item.evidence_ids,
              edge.validation_status = item.validation_status,
              edge.validation_model = $validation_model,
              edge.validation_prompt_version = $validation_prompt_version)
        """
        try:
            async with self._driver.session() as session:
                await (await session.run(
                    query,
                    cve_id=cve_id,
                    chain=[item.model_dump(mode="json") for item in chain],
                    mapping_model=mapping_model,
                    mapping_prompt_version=mapping_prompt_version,
                    validation_model=validation_model,
                    validation_prompt_version=validation_prompt_version,
                )).consume()
        except Exception as exc:
            raise GraphUnavailable("Neo4j validated attack-chain update failed") from exc

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
            nodes.append(GraphNode(id=node_id, type=labels[0].lower(), properties=properties))
        edges = [GraphEdge(**edge) for edge in record["edges"] if edge["source"] and edge["target"]]
        return EvidenceSubgraph(
            nodes=sorted(nodes, key=lambda item: (item.type, item.id)),
            edges=sorted(edges, key=lambda item: (item.source, item.relationship, item.target)),
        )
