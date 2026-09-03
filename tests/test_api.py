from fastapi.testclient import TestClient

from app.main import app


def test_health() -> None:
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_exposes_analysis_endpoint_and_retires_attack_path() -> None:
    schema = TestClient(app).get("/openapi.json").json()
    paths = schema["paths"]
    assert "/api/cve-analysis" in paths
    assert "/api/cve-analysis/{cve_id}/graph" in paths
    assert "/api/attack-path" not in paths
    analysis_schema = schema["components"]["schemas"]["CVEAnalysis"]
    assert "attack_mappings" in analysis_schema["properties"]
    assert "attack_chain" in analysis_schema["properties"]


def test_serves_dependency_free_visualization() -> None:
    response = TestClient(app).get("/visualization")

    assert response.status_code == 200
    assert "Validated ATT&amp;CK Chain" in response.text
    assert "vis-network" not in response.text
