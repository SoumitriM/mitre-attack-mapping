import asyncio
import sys
from typing import Any, cast

from neo4j import AsyncGraphDatabase

from app.cli import _analyze
from app.config import get_settings
from app.graph.repository import GraphRepository
from app.models import AttackMapping, ValidationStatus


def _yes_no(value: bool | None) -> str:
    if value is None:
        return "-"
    return "yes" if value else "no"


async def _diagnose(cve_id: str) -> None:
    analysis = cast(dict[str, Any], await _analyze(cve_id))
    mappings = [AttackMapping.model_validate(item) for item in analysis["attack_mappings"]]
    platforms = sorted(
        {
            platform
            for product in analysis["cve"]["affected_products"]
            for platform in product["platforms"]
        }
    )

    settings = get_settings()
    if settings.neo4j_password is None:
        raise RuntimeError("NEO4J_PASSWORD is required")
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password.get_secret_value()),
    )
    try:
        facts = await GraphRepository(driver).validation_facts(cve_id, mappings, platforms)
    finally:
        await driver.close()

    chain_by_step = {item["step"]: item for item in analysis["attack_chain"]}
    rows: list[list[str]] = []
    for mapping in mappings:
        fact: dict[str, Any] = facts.get(mapping.step, {})
        final = chain_by_step.get(mapping.step, {})
        validation = final.get("validation", {})
        checks = validation.get("checks", {})
        if not platforms:
            platform = "unknown"
        elif checks.get("platform_compatible"):
            platform = "compatible"
        else:
            platform = "incompatible"
        semantic = checks.get("semantic_match") if mapping.mitre_technique_id else None
        rows.append(
            [
                str(mapping.step),
                mapping.mitre_technique_id or "null",
                _yes_no(fact.get("technique_lookup_found")),
                _yes_no(fact.get("tactic_relationship_found")),
                platform if mapping.mitre_technique_id else "-",
                _yes_no(fact.get("evidence_ids_found")),
                _yes_no(semantic),
                validation.get("status", ValidationStatus.UNMAPPED.value),
            ]
        )

    headers = [
        "STEP", "TECHNIQUE", "EXISTS", "TACTIC", "PLATFORM", "EVIDENCE", "SEMANTIC", "RESULT"
    ]
    widths = [
        max([len(header), *(len(row[index]) for row in rows)])
        for index, header in enumerate(headers)
    ]
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))

    for warning in analysis["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m app.debug.validate_cve CVE-ID")
    try:
        asyncio.run(_diagnose(sys.argv[1]))
    except Exception as exc:
        print(f"diagnostics failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
