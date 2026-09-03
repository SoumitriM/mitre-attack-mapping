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

DATASETS = {
    "cwe": {
        "version": "4.20",
        "url": "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip",
    },
    "capec": {
        "version": "3.9",
        "url": "https://capec.mitre.org/data/archive/capec_v3.9.zip",
    },
    "enterprise-attack": {
        "version": "19.1",
        "url": (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "v19.1/enterprise-attack/enterprise-attack-19.1.json"
        ),
        "filename": "source.json",
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
            artifact = destination / str(metadata.get("filename", "source.zip"))
            artifact.parent.mkdir(parents=True, exist_ok=True)
            prior = previous.get(name, {})
            if artifact.is_file() and prior.get("sha256") == sha256(artifact):
                digest = str(prior["sha256"])
                retrieved_at = str(prior["retrieved_at"])
            else:
                response = await client.get(str(metadata["url"]))
                response.raise_for_status()
                artifact.write_bytes(response.content)
                digest = sha256(artifact)
                retrieved_at = datetime.now(UTC).isoformat()
            if artifact.suffix == ".zip":
                extracted = destination / "extracted"
                if not extracted.exists():
                    safe_extract(artifact, extracted)
            manifest[name] = {
                **metadata,
                "retrieved_at": retrieved_at,
                "size": artifact.stat().st_size,
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


def parse_attack(
    path: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    objects = payload.get("objects", [])
    tactics_by_short_name: dict[str, dict[str, Any]] = {}
    for item in objects:
        if (
            item.get("type") != "x-mitre-tactic"
            or item.get("revoked")
            or item.get("x_mitre_deprecated")
        ):
            continue
        external_id = next(
            (
                ref.get("external_id")
                for ref in item.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if external_id and item.get("x_mitre_shortname"):
            tactics_by_short_name[item["x_mitre_shortname"]] = {
                "id": external_id,
                "name": item.get("name"),
                "short_name": item["x_mitre_shortname"],
            }

    techniques_by_id: dict[str, dict[str, Any]] = {}
    phases_by_id: dict[str, list[dict[str, Any]]] = {}
    for item in objects:
        if item.get("type") != "attack-pattern":
            continue
        external_id = next(
            (
                ref.get("external_id")
                for ref in item.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not external_id:
            continue
        technique = {
            "id": external_id,
            "name": item.get("name"),
            "description": item.get("description", ""),
            "platforms": item.get("x_mitre_platforms", []),
            "revoked": bool(item.get("revoked")),
            "deprecated": bool(item.get("x_mitre_deprecated")),
        }
        current = techniques_by_id.get(external_id)
        current_active = (
            current is not None and not current["revoked"] and not current["deprecated"]
        )
        incoming_active = not technique["revoked"] and not technique["deprecated"]
        if current is None or (incoming_active and not current_active):
            techniques_by_id[external_id] = technique
            phases_by_id[external_id] = item.get("kill_chain_phases", [])

    links = []
    for external_id, phases in phases_by_id.items():
        for phase in phases:
            phase_name = phase.get("phase_name")
            tactic = tactics_by_short_name.get(phase_name) if isinstance(phase_name, str) else None
            if tactic:
                links.append({"technique": external_id, "tactic": tactic["id"]})
    return list(techniques_by_id.values()), list(tactics_by_short_name.values()), links


async def load_taxonomy(settings: Settings, data_root: Path) -> None:
    if settings.neo4j_password is None:
        raise ValueError("NEO4J_PASSWORD is required")
    cwe_root = data_root / "cwe" / DATASETS["cwe"]["version"] / "extracted"
    capec_root = data_root / "capec" / DATASETS["capec"]["version"] / "extracted"
    attack_file = (
        data_root
        / "enterprise-attack"
        / DATASETS["enterprise-attack"]["version"]
        / "source.json"
    )
    cwes = parse_cwe(find_xml(cwe_root, "cwec"))
    capecs, relationships = parse_capec(find_xml(capec_root, "capec"))
    if not attack_file.is_file():
        raise ValueError("downloaded archive has no Enterprise ATT&CK 19.1 STIX bundle")
    techniques, tactics, technique_tactics = parse_attack(attack_file)
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password.get_secret_value()),
    )
    try:
        async with driver.session() as session:
            for label in ("CWE", "CAPEC", "AttackTechnique", "AttackTactic"):
                await (await session.run(
                    f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS "
                    f"FOR (n:{label}) REQUIRE n.id IS UNIQUE"
                )).consume()
            for name, version in (
                ("CWE", "4.20"),
                ("CAPEC", "3.9"),
                ("ATT&CK", "19.1"),
            ):
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
            for offset in range(0, len(techniques), 500):
                await (await session.run(
                    "UNWIND $rows AS row MERGE (n:AttackTechnique {id: row.id}) "
                    "SET n.name=row.name, n.description=row.description, "
                    "n.platforms=row.platforms, n.revoked=row.revoked, "
                    "n.deprecated=row.deprecated, n.source_version='19.1'",
                    rows=techniques[offset : offset + 500],
                )).consume()
            await (await session.run(
                "UNWIND $rows AS row MERGE (n:AttackTactic {id: row.id}) "
                "SET n.name=row.name, n.short_name=row.short_name, n.source_version='19.1'",
                rows=tactics,
            )).consume()
            for offset in range(0, len(technique_tactics), 500):
                await (await session.run(
                    "UNWIND $rows AS row MATCH (technique:AttackTechnique {id: row.technique}) "
                    "MATCH (tactic:AttackTactic {id: row.tactic}) "
                    "MERGE (technique)-[r:HAS_TACTIC]->(tactic) "
                    "SET r.authoritative=true, r.source='ATT&CK', r.source_version='19.1'",
                    rows=technique_tactics[offset : offset + 500],
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
