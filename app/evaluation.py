import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models import CVEAnalysis, ValidationStatus


class ExpectedStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step: int = Field(ge=1)
    action: str
    required_action_terms: list[str] = Field(min_length=1)
    mitre_technique_id: str | None = None
    mitre_tactic_id: str | None = None


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    source_urls: list[str] = Field(min_length=1)
    review_notes: str
    expected_steps: list[ExpectedStep] = Field(min_length=1)


class EvaluationDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    reviewed_at: str
    methodology: str
    cases: list[EvaluationCase] = Field(min_length=1)


def _normalized(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def _action_matches(expected: ExpectedStep, actual_action: str) -> bool:
    action = _normalized(actual_action)
    return all(_normalized(term) in action for term in expected.required_action_terms)


def evaluate_predictions(
    dataset_path: Path, predictions_directory: Path
) -> dict[str, Any]:
    dataset = EvaluationDataset.model_validate_json(dataset_path.read_text(encoding="utf-8"))
    expected_total = predicted_total = extracted_matches = mapping_matches = 0
    predicted_mappings = unsupported_mappings = correct_chains = 0
    cases: list[dict[str, Any]] = []
    for case in dataset.cases:
        prediction_path = predictions_directory / f"{case.cve_id}.json"
        if prediction_path.is_file():
            prediction = CVEAnalysis.model_validate_json(
                prediction_path.read_text(encoding="utf-8")
            )
            actual_steps = {item.step: item for item in prediction.exploit_steps}
            actual_chain = {item.step: item for item in prediction.attack_chain}
        else:
            actual_steps = {}
            actual_chain = {}
        case_extract = case_mapping = 0
        for expected in case.expected_steps:
            actual_step = actual_steps.get(expected.step)
            extracted = bool(
                actual_step and _action_matches(expected, actual_step.action)
            )
            extracted_matches += int(extracted)
            case_extract += int(extracted)
            final = actual_chain.get(expected.step)
            if final and final.proposed_technique_id is not None:
                predicted_mappings += 1
            correct_mapping = bool(
                final
                and final.proposed_technique_id == expected.mitre_technique_id
                and final.mitre_tactic_id == expected.mitre_tactic_id
                and (
                    (expected.mitre_technique_id is not None
                     and final.validation.status == ValidationStatus.VALIDATED)
                    or (expected.mitre_technique_id is None
                        and final.validation.status == ValidationStatus.UNMAPPED)
                )
            )
            mapping_matches += int(correct_mapping)
            case_mapping += int(correct_mapping)
            if final and final.proposed_technique_id is not None and not correct_mapping:
                unsupported_mappings += 1
        expected_total += len(case.expected_steps)
        predicted_total += len(actual_steps)
        exact = (
            len(actual_steps) == len(case.expected_steps)
            and len(actual_chain) == len(case.expected_steps)
            and case_extract == len(case.expected_steps)
            and case_mapping == len(case.expected_steps)
        )
        correct_chains += int(exact)
        cases.append({
            "cve_id": case.cve_id,
            "prediction_found": prediction_path.is_file(),
            "expected_steps": len(case.expected_steps),
            "predicted_steps": len(actual_steps),
            "extraction_matches": case_extract,
            "mapping_matches": case_mapping,
            "end_to_end_correct": exact,
        })
    extraction_precision = (
        extracted_matches / predicted_total if predicted_total else 0.0
    )
    extraction_recall = extracted_matches / expected_total if expected_total else 0.0
    return {
        "dataset_version": dataset.version,
        "case_count": len(dataset.cases),
        "metrics": {
            "exploit_step_extraction_accuracy": extraction_recall,
            "exploit_step_extraction_precision": extraction_precision,
            "exploit_step_extraction_recall": extraction_recall,
            "attack_technique_mapping_accuracy": (
                mapping_matches / expected_total if expected_total else 0.0
            ),
            "unsupported_mapping_rate": (
                unsupported_mappings / predicted_mappings if predicted_mappings else 0.0
            ),
            "end_to_end_chain_correctness": (
                correct_chains / len(dataset.cases) if dataset.cases else 0.0
            ),
        },
        "counts": {
            "expected_steps": expected_total,
            "predicted_steps": predicted_total,
            "matched_steps": extracted_matches,
            "correct_mappings": mapping_matches,
            "predicted_non_null_mappings": predicted_mappings,
            "unsupported_mappings": unsupported_mappings,
            "correct_chains": correct_chains,
        },
        "cases": cases,
    }
