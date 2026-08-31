import asyncio
import json

import httpx
import typer
from neo4j import AsyncGraphDatabase

from app.analysis import CVEAnalysisService
from app.config import get_settings
from app.enrichment.attack_mapper import FHGenieAttackMapper
from app.enrichment.fh_genie import FHGenieEvidenceAgent
from app.enrichment.validation_agent import FHGenieValidationAgent
from app.graph.repository import GraphRepository

cli = typer.Typer(no_args_is_help=True)


@cli.callback()
def root() -> None:
    """Extract evidence-grounded exploit steps from CVE advisories."""


async def _analyze(cve_id: str) -> dict[str, object]:
    settings = get_settings()
    if settings.neo4j_password is None:
        raise RuntimeError("NEO4J_PASSWORD is required")
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password.get_secret_value()),
    )
    try:
        graph = GraphRepository(driver)
        await graph.initialize()
        try:
            agent = FHGenieEvidenceAgent(settings)
            mapper = FHGenieAttackMapper(settings, agent.client)
            validator = FHGenieValidationAgent(settings, agent.client)
        except ValueError:
            agent = None
            mapper = None
            validator = None
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            service = CVEAnalysisService(
                settings, graph, client, agent, mapper, validator
            )
            result = await service.analyze(cve_id)
        return result.model_dump(mode="json")
    finally:
        await driver.close()


@cli.command()
def analyze(cve_id: str) -> None:
    """Analyze a CVE and print evidence-grounded exploit steps."""
    try:
        record = asyncio.run(_analyze(cve_id))
    except (ValueError, RuntimeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(record, indent=2))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
