from pathlib import Path


def test_configuration_script_keeps_neo4j_isolated() -> None:
    script = Path("scripts/configure_from_incident_env.py").read_text(encoding="utf-8")
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert '"NEO4J_URI": "bolt://localhost:7688"' in script
    assert '"MITRE_NEO4J_HTTP_PORT": "7475"' in script
    assert "name: mitre-attack-chain" in compose
    assert "name: mitre-attack-chain-neo4j-data" in compose
