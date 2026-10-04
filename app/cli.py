import asyncio
import json
from pathlib import Path
from typing import Annotated, Literal, cast

import httpx
import typer
from neo4j import AsyncGraphDatabase
from openai import AsyncOpenAI

from app.analysis import CVEAnalysisService
from app.api.routes import compact_analysis_view
from app.config import get_settings
from app.enrichment.attack_mapper import FHGenieAttackMapper
from app.enrichment.candidate_retrieval import EmbeddingClient, RerankClient
from app.enrichment.ctid_mapper import FHGenieCTIDCVEMapper
from app.enrichment.fh_genie import AsyncCompatibleClient, FHGenieEvidenceAgent
from app.evaluation import evaluate_predictions
from app.graph.repository import GraphRepository, GraphUnavailable
from app.models import CVEAnalysis

cli = typer.Typer(no_args_is_help=True)


@cli.callback()
def root() -> None:
    """Extract evidence-grounded exploit steps from CVE advisories."""


async def _analyze_many(
    cve_ids: list[str], description_source: Literal["auto", "advisories", "opencve"] = "auto"
) -> list[dict[str, object]]:
    settings = get_settings()
    if settings.neo4j_password is None:
        raise RuntimeError("NEO4J_PASSWORD is required")
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password.get_secret_value()),
    )
    try:
        agent: FHGenieEvidenceAgent | None
        mapper: FHGenieAttackMapper | None
        ctid_mapper: FHGenieCTIDCVEMapper | None
        downstream_client: AsyncCompatibleClient | None
        try:
            if settings.ctid_only_mode:
                if not (
                    settings.fh_genie_key and settings.fh_genie_base_url and settings.fh_genie_model
                ):
                    raise ValueError("FH Genie is required for CTID-only mode")
                downstream_client = cast(
                    AsyncCompatibleClient,
                    AsyncOpenAI(
                        api_key=settings.fh_genie_key.get_secret_value(),
                        base_url=settings.fh_genie_base_url,
                    ),
                )
                agent = None
                mapper = None
                ctid_mapper = FHGenieCTIDCVEMapper(settings.fh_genie_model, downstream_client)
            else:
                agent = FHGenieEvidenceAgent(settings)
                downstream_client = agent.downstream_client
                mapper = FHGenieAttackMapper(settings, downstream_client)
                ctid_mapper = (
                    FHGenieCTIDCVEMapper(mapper.model, downstream_client)
                    if settings.enable_ctid_mapping
                    else None
                )
        except ValueError:
            agent = None
            mapper = None
            ctid_mapper = None
            downstream_client = None
        graph = GraphRepository(
            driver,
            cast(EmbeddingClient, downstream_client) if downstream_client else None,
            settings.fh_genie_embedding_model if downstream_client else None,
            cast(RerankClient, downstream_client) if downstream_client else None,
            settings.downstream_model if downstream_client else None,
            settings.attack_embedding_cache_path,
        )
        await graph.initialize()
        async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
            service = CVEAnalysisService(
                settings, graph, client, agent, mapper, ctid_mapper
            )
            results = [
                await service.analyze(cve_id, description_source=description_source)
                for cve_id in cve_ids
            ]
        return [result.model_dump(mode="json") for result in results]
    finally:
        await driver.close()


async def _initialize_attack_embedding_cache() -> int:
    settings = get_settings()
    if settings.neo4j_password is None:
        raise RuntimeError("NEO4J_PASSWORD is required")
    if settings.fh_genie_key is None or settings.fh_genie_base_url is None:
        raise RuntimeError("FH Genie embedding configuration is required")
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password.get_secret_value()),
    )
    client = AsyncOpenAI(
        api_key=settings.fh_genie_key.get_secret_value(),
        base_url=settings.fh_genie_base_url,
    )
    try:
        graph = GraphRepository(
            driver,
            cast(EmbeddingClient, client),
            settings.fh_genie_embedding_model,
            attack_embedding_cache_path=settings.attack_embedding_cache_path,
        )
        return await graph.initialize_description_embedding_cache()
    finally:
        await driver.close()


@cli.command()
def analyze(
    cve_ids: list[str],
    output: Annotated[
        Path | None,
        typer.Option(help="Write pretty-printed batch JSON to this file"),
    ] = None,
    description_source: Annotated[
        str, typer.Option(help="Evidence source: auto (description first), advisories, or opencve")
    ] = "auto",
    full: Annotated[
        bool,
        typer.Option(help="Include advisories, evidence, and internal analysis fields"),
    ] = False,
) -> None:
    """Analyze one or more CVEs and print them as one JSON array."""
    try:
        if description_source not in {"auto", "advisories", "opencve"}:
            raise ValueError("description-source must be auto, advisories or opencve")
        records = asyncio.run(
            _analyze_many(
                cve_ids, cast(Literal["auto", "advisories", "opencve"], description_source)
            )
        )
    except (ValueError, RuntimeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    output_records = (
        records
        if full
        else [
            compact_analysis_view(CVEAnalysis.model_validate(record)).model_dump(mode="json")
            for record in records
        ]
    )
    rendered = json.dumps(output_records, indent=2)
    if output is None:
        typer.echo(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered + "\n", encoding="utf-8")
    typer.echo(f"Wrote {len(records)} CVE analyses to {output}", err=True)


@cli.command("initialize-attack-embedding-cache")
def initialize_attack_embedding_cache() -> None:
    """Precompute and persist ATT&CK corpus embeddings outside CVE requests."""
    try:
        count = asyncio.run(_initialize_attack_embedding_cache())
    except (GraphUnavailable, RuntimeError) as exc:
        typer.echo(f"ATT&CK embedding cache initialization failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Cached embeddings for {count} ATT&CK techniques")


@cli.command()
def evaluate(
    predictions: Annotated[
        Path, typer.Argument(help="Directory containing one CVEAnalysis JSON file per CVE")
    ],
    dataset: Annotated[Path, typer.Option(help="Reviewed evaluation dataset")] = Path(
        "evaluations/dataset.json"
    ),
) -> None:
    """Score saved analyses without making network or model calls."""
    try:
        report = evaluate_predictions(dataset, predictions)
    except (OSError, ValueError) as exc:
        typer.echo(f"Evaluation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(report, indent=2))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
