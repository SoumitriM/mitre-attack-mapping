import asyncio
import json

import typer

from app.config import get_settings
from app.ingestion.service import CVEIngestionService, CVENotAvailable, InvalidCVEID

cli = typer.Typer(no_args_is_help=True)


@cli.callback()
def root() -> None:
    """Build evidence-grounded CVE records and attack paths."""


@cli.command()
def analyze(cve_id: str) -> None:
    """Retrieve and print a normalized CVE record."""
    try:
        record = asyncio.run(CVEIngestionService(get_settings()).analyze(cve_id))
    except (InvalidCVEID, CVENotAvailable) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(record.model_dump(mode="json"), indent=2))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
