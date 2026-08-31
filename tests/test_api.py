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
    assert "/api/attack-path" not in paths
    analysis_schema = schema["components"]["schemas"]["CVEAnalysis"]
    assert "attack_mappings" in analysis_schema["properties"]
