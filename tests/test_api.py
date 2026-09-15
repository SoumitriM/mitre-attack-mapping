from fastapi.testclient import TestClient

from app.api.routes import compact_analysis_view
from app.main import app
from app.models import CVEAnalysis


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


def test_compact_analysis_view_contains_only_mapping_views() -> None:
    result = CVEAnalysis.model_validate({
        "cve": {"cve_id": "CVE-2026-22306"},
        "attack_chain": [{
            "step": 1,
            "action": "Execute payload",
            "proposed_technique_id": None,
            "mitre_tactic_id": None,
            "evidence_ids": [],
            "validation": {
                "status": "unmapped",
                "checks": {
                    "technique_exists": False,
                    "tactic_valid": False,
                    "platform_compatible": False,
                    "evidence_support": False,
                    "semantic_match": False,
                },
                "reasoning": "No supported mapping.",
                "validator_confidence": 0.0,
            },
        }],
        "cve_level_attack_mappings": {
            "exploitation_techniques": [{
                "id": "ET-1", "action": "Exploit overflow",
                "mitre_technique_id": "T1203", "mitre_tactic_id": "TA0002",
                "reasoning": "Validated.", "confidence": 0.9,
                "evidence_ids": ["ev-1"], "processing_status": "completed",
                "validation": {
                    "status": "validated",
                    "checks": {
                        "technique_exists": True, "tactic_valid": True,
                        "platform_compatible": True, "evidence_support": True,
                        "semantic_match": True,
                    },
                    "reasoning": "Validated.", "validator_confidence": 0.9,
                },
            }],
            "primary_impacts": [{
                "id": "PI-1", "action": "Obtain code execution", "enabled_by": ["ET-1"],
                "mitre_technique_id": None, "mitre_tactic_id": None,
                "reasoning": "Direct impact.", "confidence": 0.0,
                "evidence_ids": ["ev-1"], "processing_status": "completed",
            }],
            "secondary_impacts": [],
        },
        "warnings": ["not exposed"],
    })

    compact = compact_analysis_view(result).model_dump(mode="json")

    assert set(compact) == {"attack_chain", "ctid_map"}
    assert compact["attack_chain"] == [{
        "step": 1, "action": "Execute payload", "technique_id": None,
        "tactic_id": None, "status": "unmapped",
    }]
    assert compact["ctid_map"]["exploitation_techniques"][0]["technique_id"] == "T1203"
    assert compact["ctid_map"]["primary_impacts"][0]["enabled_by"] == ["ET-1"]
    assert "warnings" not in compact
