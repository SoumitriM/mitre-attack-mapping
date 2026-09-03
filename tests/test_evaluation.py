import json
from pathlib import Path

from app.evaluation import evaluate_predictions
from app.models import (
    CVEAnalysis,
    CVERecord,
    ExploitStep,
    ValidatedAttackStep,
    ValidationChecks,
    ValidationDetails,
    ValidationStatus,
)


def write_dataset(path: Path) -> None:
    path.write_text(json.dumps({
        "version": "test-v1",
        "reviewed_at": "2026-08-31",
        "methodology": "Manual fixture",
        "cases": [{
            "cve_id": "CVE-2026-22306",
            "source_urls": ["https://research.example/advisory"],
            "review_notes": "Reviewed fixture",
            "expected_steps": [{
                "step": 1,
                "action": "Download malicious archive",
                "required_action_terms": ["download", "archive"],
                "mitre_technique_id": "T1105",
                "mitre_tactic_id": "TA0011",
            }],
        }],
    }), encoding="utf-8")


def prediction() -> CVEAnalysis:
    step = ExploitStep.model_validate({
        "step": 1,
        "action": "Download the malicious update archive",
        "outcome": "Archive reaches host",
        "evidence": [{
            "source_url": "https://research.example/advisory",
            "supporting_text": "The client downloads the archive.",
        }],
    })
    final = ValidatedAttackStep(
        step=1,
        action=step.action,
        proposed_technique_id="T1105",
        mitre_tactic_id="TA0011",
        evidence_ids=["evidence-1"],
        validation=ValidationDetails(
            status=ValidationStatus.VALIDATED,
            checks=ValidationChecks(
                technique_exists=True,
                tactic_valid=True,
                platform_compatible=True,
                evidence_support=True,
                semantic_match=True,
            ),
            reasoning="The evidence supports file transfer.",
            validator_confidence=0.9,
        ),
    )
    return CVEAnalysis(
        cve=CVERecord(cve_id="CVE-2026-22306"),
        exploit_steps=[step],
        attack_chain=[final],
    )


def test_evaluation_scores_a_correct_end_to_end_chain(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.json"
    predictions = tmp_path / "predictions"
    predictions.mkdir()
    write_dataset(dataset)
    (predictions / "CVE-2026-22306.json").write_text(
        prediction().model_dump_json(), encoding="utf-8"
    )

    report = evaluate_predictions(dataset, predictions)

    assert report["metrics"] == {
        "exploit_step_extraction_accuracy": 1.0,
        "exploit_step_extraction_precision": 1.0,
        "exploit_step_extraction_recall": 1.0,
        "attack_technique_mapping_accuracy": 1.0,
        "unsupported_mapping_rate": 0.0,
        "end_to_end_chain_correctness": 1.0,
    }


def test_evaluation_counts_an_unsupported_mapping(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.json"
    predictions = tmp_path / "predictions"
    predictions.mkdir()
    write_dataset(dataset)
    wrong = prediction()
    wrong.attack_chain[0].proposed_technique_id = "T1190"
    wrong.attack_chain[0].mitre_tactic_id = "TA0001"
    (predictions / "CVE-2026-22306.json").write_text(
        wrong.model_dump_json(), encoding="utf-8"
    )

    report = evaluate_predictions(dataset, predictions)

    assert report["metrics"]["attack_technique_mapping_accuracy"] == 0.0
    assert report["metrics"]["unsupported_mapping_rate"] == 1.0
    assert report["metrics"]["end_to_end_chain_correctness"] == 0.0
