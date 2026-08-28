import argparse
import asyncio
import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import httpx
from neo4j import AsyncGraphDatabase

from app.config import Settings

CVELIST_COMMIT = "7d372af27f6929c1994de2bad584f69a7162839e"
DATASETS = {
    "cwe": {
        "version": "4.20",
        "url": "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip",
    },
    "capec": {
        "version": "3.9",
        "url": "https://capec.mitre.org/data/archive/capec_v3.9.zip",
    },
    "cvelist-v5": {
        "version": CVELIST_COMMIT,
        "url": f"https://github.com/CVEProject/cvelistV5/archive/{CVELIST_COMMIT}.zip",
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_extract(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            target = (destination / member.filename).resolve()
            if not target.is_relative_to(root):
                raise ValueError("dataset archive contains an unsafe path")
        bundle.extractall(destination)


async def download_all(data_root: Path) -> dict[str, dict[str, Any]]:
    manifest_path = data_root.parent / "manifest.json"
    previous = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    manifest: dict[str, dict[str, Any]] = {}
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        for name, metadata in DATASETS.items():
            destination = data_root / name / str(metadata["version"])
            archive = destination / "source.zip"
            archive.parent.mkdir(parents=True, exist_ok=True)
            prior = previous.get(name, {})
            if archive.is_file() and prior.get("sha256") == sha256(archive):
                digest = str(prior["sha256"])
                retrieved_at = str(prior["retrieved_at"])
            else:
                response = await client.get(str(metadata["url"]))
                response.raise_for_status()
                archive.write_bytes(response.content)
                digest = sha256(archive)
                retrieved_at = datetime.now(UTC).isoformat()
            extracted = destination / "extracted"
            if not extracted.exists():
                safe_extract(archive, extracted)
            manifest[name] = {
                **metadata,
                "retrieved_at": retrieved_at,
                "size": archive.stat().st_size,
                "sha256": digest,
            }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def find_xml(root: Path, prefix: str) -> Path:
    candidates = sorted(root.rglob(f"{prefix}*.xml"))
    if not candidates:
        raise ValueError(f"downloaded archive has no {prefix} XML document")
    return candidates[0]


def parse_cwe(path: Path) -> list[dict[str, Any]]:
    root = ElementTree.parse(path).getroot()
    return [
        {
            "id": f"CWE-{item.attrib['ID']}",
            "name": item.attrib.get("Name"),
            "status": item.attrib.get("Status"),
            "deprecated": item.attrib.get("Status") == "Deprecated",
        }
        for item in root.findall(".//{*}Weakness")
        if item.attrib.get("ID")
    ]


def parse_capec(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    root = ElementTree.parse(path).getroot()
    patterns = []
    relationships = []
    for item in root.findall(".//{*}Attack_Pattern"):
        if not item.attrib.get("ID"):
            continue
        capec_id = f"CAPEC-{item.attrib['ID']}"
        patterns.append(
            {
                "id": capec_id,
                "name": item.attrib.get("Name"),
                "status": item.attrib.get("Status"),
                "deprecated": item.attrib.get("Status") == "Deprecated",
            }
        )
        for weakness in item.findall(".//{*}Related_Weakness"):
            if weakness.attrib.get("CWE_ID"):
                relationships.append(
                    {"cwe": f"CWE-{weakness.attrib['CWE_ID']}", "capec": capec_id}
                )
    return patterns, relationships


async def load_taxonomy(settings: Settings, data_root: Path) -> None:
    if settings.neo4j_password is None:
        raise ValueError("NEO4J_PASSWORD is required")
    cwe_root = data_root / "cwe" / DATASETS["cwe"]["version"] / "extracted"
    capec_root = data_root / "capec" / DATASETS["capec"]["version"] / "extracted"
    cwes = parse_cwe(find_xml(cwe_root, "cwec"))
    capecs, relationships = parse_capec(find_xml(capec_root, "capec"))
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password.get_secret_value()),
    )
    try:
        async with driver.session() as session:
            for label in ("CWE", "CAPEC"):
                await (await session.run(
                    f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS "
                    f"FOR (n:{label}) REQUIRE n.id IS UNIQUE"
                )).consume()
            for name, version in (("CWE", "4.20"), ("CAPEC", "3.9")):
                await (await session.run(
                    "MERGE (r:DatasetRelease {name: $name, version: $version}) "
                    "SET r.loaded_at = $loaded_at",
                    name=name,
                    version=version,
                    loaded_at=datetime.now(UTC).isoformat(),
                )).consume()
            for rows, label, version in ((cwes, "CWE", "4.20"), (capecs, "CAPEC", "3.9")):
                for offset in range(0, len(rows), 500):
                    await (await session.run(
                        f"UNWIND $rows AS row MERGE (n:{label} {{id: row.id}}) "
                        "SET n.name=row.name, n.status=row.status, n.deprecated=row.deprecated, "
                        "n.source_version=$version",
                        rows=rows[offset : offset + 500],
                        version=version,
                    )).consume()
            for offset in range(0, len(relationships), 500):
                await (await session.run(
                    "UNWIND $rows AS row MATCH (cwe:CWE {id: row.cwe}) "
                    "MATCH (capec:CAPEC {id: row.capec}) "
                    "MERGE (cwe)-[r:RELATED_TO_CAPEC]->(capec) "
                    "SET r.authoritative=true, r.source='CAPEC', r.source_version='3.9'",
                    rows=relationships[offset : offset + 500],
                )).consume()
    finally:
        await driver.close()


async def sync(download_only: bool = False) -> None:
    settings = Settings()
    data_root = Path("data/raw")
    await download_all(data_root)
    if not download_only:
        await load_taxonomy(settings, data_root)


def main() -> None:
    parser = argparse.ArgumentParser(description="Synchronize pinned MITRE datasets")
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args()
    asyncio.run(sync(download_only=args.download_only))


if __name__ == "__main__":
    main()
