"""Create this project's .env using FH Genie settings from incident-resolution-ai."""

from pathlib import Path
from secrets import token_urlsafe

SOURCE_KEYS = ("FH_GENIE_KEY", "FH_GENIE_BASE_URL", "FH_GENIE_MODEL", "NVD_API_KEY")


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    source_path = project_root.parent / "incident-resolution-ai" / ".env"
    target_path = project_root / ".env"
    if not source_path.is_file():
        raise SystemExit(f"Source environment file not found: {source_path}")

    source = read_env(source_path)
    missing = [key for key in SOURCE_KEYS[:3] if not source.get(key)]
    if missing:
        raise SystemExit(f"Source environment is missing: {', '.join(missing)}")

    existing = read_env(target_path) if target_path.is_file() else {}
    values = {
        "NVD_API_KEY": source.get("NVD_API_KEY", existing.get("NVD_API_KEY", "")),
        "HTTP_TIMEOUT_SECONDS": existing.get("HTTP_TIMEOUT_SECONDS", "15"),
        "HTTP_MAX_RETRIES": existing.get("HTTP_MAX_RETRIES", "3"),
        "CACHE_TTL_SECONDS": existing.get("CACHE_TTL_SECONDS", "3600"),
        "CVELIST_V5_ROOT": existing.get("CVELIST_V5_ROOT", "data/raw/cvelist-v5"),
        "ADVISORY_ALLOWED_DOMAINS": existing.get(
            "ADVISORY_ALLOWED_DOMAINS", "offseq.com"
        ),
        "ADVISORY_MAX_BYTES": existing.get("ADVISORY_MAX_BYTES", "2000000"),
        "FH_GENIE_KEY": source["FH_GENIE_KEY"],
        "FH_GENIE_BASE_URL": source["FH_GENIE_BASE_URL"],
        "FH_GENIE_MODEL": source["FH_GENIE_MODEL"],
        "NEO4J_URI": "bolt://localhost:7688",
        "NEO4J_USERNAME": "neo4j",
        "NEO4J_PASSWORD": existing.get("NEO4J_PASSWORD") or token_urlsafe(32),
        "MITRE_NEO4J_HTTP_PORT": "7475",
        "MITRE_NEO4J_BOLT_PORT": "7688",
    }
    temporary = project_root / ".env.configure.tmp"
    temporary.write_text(
        "# Generated from incident-resolution-ai/.env; do not commit.\n"
        + "\n".join(f"{key}={value}" for key, value in values.items())
        + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(target_path)
    print("Configured FH Genie and isolated MITRE Neo4j settings in .env")


if __name__ == "__main__":
    main()
