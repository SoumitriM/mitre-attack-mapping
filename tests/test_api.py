from inspect import signature

from fastapi.testclient import TestClient

from app.api.routes import AnalyzeRequest, analyze, compact_analysis_view
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
    assert "/api/cve-analysis/{cve_id}/graph" not in paths
    assert "/api/attack-path" not in paths
    analysis_schema = schema["components"]["schemas"]["CVEAnalysis"]
    assert "attack_mappings" in analysis_schema["properties"]
    assert "attack_chain" in analysis_schema["properties"]


def test_compact_response_is_the_default_and_full_response_can_be_requested() -> None:
    assert signature(analyze).parameters["compact"].default is True


def test_analysis_request_accepts_an_array_of_cves() -> None:
    request = AnalyzeRequest(cve_ids=["CVE-2026-22306", "CVE-2025-0282"])

    assert request.cve_ids == ["CVE-2026-22306", "CVE-2025-0282"]


def test_analysis_request_rejects_an_empty_array() -> None:
    response = TestClient(app).post("/api/cve-analysis", json={"cve_ids": []})

    assert response.status_code == 422


def test_does_not_expose_a_persisted_cve_visualization() -> None:
    response = TestClient(app).get("/visualization")

    assert response.status_code == 404


def test_compact_analysis_view_contains_only_mapping_views() -> None:
    result = CVEAnalysis.model_validate(
        {
            "cve": {"cve_id": "CVE-2026-22306", "description": "Test description"},
            "exploit_steps": [
                {
                    "step": 1,
                    "action": "Execute payload",
                    "outcome": "Code execution",
                    "evidence": [
                        {
                            "source_url": "https://research.example/advisory",
                            "supporting_text": "The payload executes.",
                        }
                    ],
                }
            ],
            "attack_chain": [
                {
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
                }
            ],
            "cve_level_attack_mappings": {
                "exploitation_techniques": [
                    {
                        "id": "ET-1",
                        "action": "Exploit overflow",
                        "mitre_technique_id": "T1203",
                        "mitre_tactic_id": "TA0002",
                        "reasoning": "Validated.",
                        "confidence": 0.9,
                        "evidence_ids": ["ev-1"],
                        "processing_status": "completed",
                        "validation": {
                            "status": "validated",
                            "checks": {
                                "technique_exists": True,
                                "tactic_valid": True,
                                "platform_compatible": True,
                                "evidence_support": True,
                                "semantic_match": True,
                            },
                            "reasoning": "Validated.",
                            "validator_confidence": 0.9,
                        },
                    }
                ],
                "primary_impacts": [
                    {
                        "id": "PI-1",
                        "action": "Obtain code execution",
                        "enabled_by": ["ET-1"],
                        "mitre_technique_id": None,
                        "mitre_tactic_id": None,
                        "reasoning": "Direct impact.",
                        "confidence": 0.0,
                        "evidence_ids": ["ev-1"],
                        "processing_status": "completed",
                    }
                ],
                "secondary_impacts": [],
            },
            "warnings": ["not exposed"],
        }
    )

    compact = compact_analysis_view(result).model_dump(mode="json")

    assert set(compact) == {"cve_id", "attack_chain", "ctid_map"}
    assert compact["cve_id"] == "CVE-2026-22306"
    assert compact["attack_chain"] == [
        {
            "step": 1,
            "action": "Execute payload",
            "technique_id": None,
            "tactic_id": None,
            "technique_name": None,
            "tactic_name": None,
            "confidence": 0.0,
            "mapped": False,
        }
    ]
    assert compact["ctid_map"]["exploitation_techniques"][0]["technique_id"] == "T1203"
    assert compact["ctid_map"]["primary_impacts"][0]["enabled_by"] == ["ET-1"]
    assert "warnings" not in compact
