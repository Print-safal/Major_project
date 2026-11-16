import json
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import Mock

from rag_int.confidence import DEFAULT_WEIGHTS
from rag_int.rag_llm_150_case_eval import (
    DATASET_MODES,
    BenchmarkIntegrityError,
    build_resume_signature,
    calculate_metrics,
    load_existing_results,
    load_cases,
    preserve_prior_errors,
    validate_cases,
    validate_resume_records,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def result(test_id, cwe, *, status="completed", passed=True, predicted=None):
    if status == "error":
        return {
            "test_id": test_id,
            "ground_truth_cwe": cwe,
            "status": "error",
            "error": "provider unavailable",
            "predicted_vulnerable": None,
            "predicted_cwes": [],
        }
    if predicted is None:
        predicted = [cwe] if cwe else []
    return {
        "test_id": test_id,
        "ground_truth_cwe": cwe,
        "status": "completed",
        "pass": passed,
        "predicted_vulnerable": cwe is not None,
        "predicted_cwes": predicted,
    }


def signature(cases, *, contextual=False, shadow=False, prompt="same prompt", weights=None):
    return build_resume_signature(
        cases=cases,
        dataset_sha256="a" * 64,
        mode="test",
        contextual_enabled=contextual,
        shadow_enabled=shadow,
        prompt_text=prompt,
        weights=weights,
    )


class CalculateMetricsTests(unittest.TestCase):
    def test_completed_correct_and_incorrect_cases(self):
        metrics = calculate_metrics([
            result("V1", "CWE-89", passed=True),
            result("V2", "CWE-89", passed=False, predicted=[]),
        ], expected_total=2)
        self.assertEqual(metrics["attempted_count"], 2)
        self.assertEqual(metrics["completed_count"], 2)
        self.assertEqual(metrics["correct_count"], 1)
        self.assertEqual(metrics["incorrect_count"], 1)
        self.assertEqual(metrics["error_count"], 0)
        self.assertEqual(metrics["overall_case_accuracy"], 0.5)

    def test_api_errors_are_excluded_from_accuracy(self):
        metrics = calculate_metrics([
            result("V1", "CWE-89", passed=True),
            result("V2", "CWE-89", status="error"),
        ], expected_total=2)
        self.assertEqual(metrics["attempted_count"], 2)
        self.assertEqual(metrics["completed_count"], 1)
        self.assertEqual(metrics["correct_count"], 1)
        self.assertEqual(metrics["incorrect_count"], 0)
        self.assertEqual(metrics["error_count"], 1)
        self.assertEqual(metrics["completion_rate"], 0.5)
        self.assertEqual(metrics["overall_case_accuracy"], 1.0)
        self.assertEqual(metrics["per_cwe"]["CWE-89"], {
            "total": 1, "correct": 1, "incorrect": 0, "accuracy": 1.0,
        })

    def test_zero_completed_cases_report_null_metrics(self):
        metrics = calculate_metrics([
            result("V1", "CWE-89", status="error"),
            result("S1", None, status="error"),
        ], expected_total=2)
        for key in (
            "overall_case_accuracy", "vulnerable_cwe_accuracy", "safe_code_accuracy",
            "strict_exact_cwe_accuracy", "precision", "recall", "f1",
        ):
            self.assertIsNone(metrics[key], key)
        self.assertEqual(metrics["completed_count"], 0)
        self.assertEqual(metrics["error_count"], 2)
        self.assertTrue(all(value["accuracy"] is None for value in metrics["per_cwe"].values()))

    def test_safe_and_vulnerable_metrics_use_completed_categories(self):
        metrics = calculate_metrics([
            result("V1", "CWE-89", passed=True),
            result("S1", None, passed=True),
            result("S2", None, status="error"),
        ], expected_total=3)
        self.assertEqual(metrics["vulnerable_completed_count"], 1)
        self.assertEqual(metrics["safe_completed_count"], 1)
        self.assertEqual(metrics["vulnerable_cwe_accuracy"], 1.0)
        self.assertEqual(metrics["safe_code_accuracy"], 1.0)
        self.assertEqual(metrics["binary_confusion"], {"tp": 1, "tn": 1, "fp": 0, "fn": 0})

    def test_per_cwe_accuracy_uses_completed_cases_only(self):
        metrics = calculate_metrics([
            result("V1", "CWE-22", passed=True),
            result("V2", "CWE-22", passed=False, predicted=[]),
            result("V3", "CWE-22", status="error"),
        ], expected_total=3)
        self.assertEqual(metrics["per_cwe"]["CWE-22"], {
            "total": 2, "correct": 1, "incorrect": 1, "accuracy": 0.5,
        })
        self.assertIsNone(metrics["per_cwe"]["CWE-78"]["accuracy"])


class DatasetValidationTests(unittest.TestCase):
    def test_full_150_dataset_validation(self):
        cases = load_cases(DATASET_MODES["full150"]["path"], "full150")
        self.assertEqual(len(cases), 150)

    def test_approved_30_case_subset_validation(self):
        cases = load_cases(DATASET_MODES["preliminary30"]["path"], "preliminary30")
        self.assertEqual(len(cases), 30)

    def test_dataset_hash_mismatch_is_rejected(self):
        spec = DATASET_MODES["preliminary30"]
        cases = load_cases(spec["path"], "preliminary30")
        with self.assertRaisesRegex(BenchmarkIntegrityError, "SHA-256"):
            validate_cases(cases, "preliminary30", "0" * 64)

    def test_modified_or_truncated_dataset_is_rejected(self):
        spec = DATASET_MODES["preliminary30"]
        cases = load_cases(spec["path"], "preliminary30")
        with self.assertRaises(BenchmarkIntegrityError):
            validate_cases(cases[:-1], "preliminary30", spec["sha256"])

    def test_duplicate_dataset_ids_are_rejected(self):
        spec = DATASET_MODES["preliminary30"]
        cases = load_cases(spec["path"], "preliminary30")
        cases[1] = {**cases[1], "test_id": cases[0]["test_id"]}
        with self.assertRaisesRegex(BenchmarkIntegrityError, "duplicate test IDs"):
            validate_cases(cases, "preliminary30", spec["sha256"])


class ResumeValidationTests(unittest.TestCase):
    def setUp(self):
        self.cases = [
            {"test_id": "V1", "ground_truth_cwe": "CWE-89", "code": "x = 1"},
            {"test_id": "S1", "ground_truth_cwe": None, "code": "y = 2"},
        ]

    def test_duplicate_saved_ids_are_rejected(self):
        row = result("V1", "CWE-89")
        with self.assertRaisesRegex(BenchmarkIntegrityError, "Duplicate"):
            validate_resume_records([row, dict(row)], self.cases)

    def test_missing_and_unexpected_saved_ids_are_rejected(self):
        with self.assertRaisesRegex(BenchmarkIntegrityError, "missing a valid test_id"):
            validate_resume_records([{"status": "error", "error": "x"}], self.cases)
        with self.assertRaisesRegex(BenchmarkIntegrityError, "Unexpected"):
            validate_resume_records([result("OTHER", "CWE-89")], self.cases)

    def test_unattempted_dataset_cases_are_valid_pending_work(self):
        self.assertEqual(validate_resume_records([result("V1", "CWE-89")], self.cases)[0]["test_id"], "V1")

    def test_retry_preserves_prior_api_error_details(self):
        previous = result("V1", "CWE-89", status="error")
        retried = preserve_prior_errors(result("V1", "CWE-89"), previous)
        self.assertEqual(retried["status"], "completed")
        self.assertEqual(retried["prior_error_attempts"], [{"error": "provider unavailable"}])

    def test_incorrect_ground_truth_label_is_rejected(self):
        with self.assertRaisesRegex(BenchmarkIntegrityError, "Ground-truth"):
            validate_resume_records([result("V1", "CWE-78")], self.cases)

    def test_feature_flag_mismatch_is_rejected(self):
        original = signature(self.cases, contextual=False)
        changed = signature(self.cases, contextual=True)
        self.assertNotEqual(original, changed)
        self._assert_signature_rejected(original, changed)

    def test_prompt_and_scoring_mismatch_are_rejected(self):
        original = signature(self.cases)
        prompt_changed = signature(self.cases, prompt="changed prompt")
        weights_changed = signature(self.cases, weights=replace(DEFAULT_WEIGHTS, llm_consistency=24.0,
                                                                 safeguards=16.0))
        self._assert_signature_rejected(original, prompt_changed)
        self._assert_signature_rejected(original, weights_changed)

    def test_dataset_hash_mismatch_is_rejected(self):
        original = build_resume_signature(self.cases, "a" * 64, "test", False, False)
        changed = build_resume_signature(self.cases, "b" * 64, "test", False, False)
        self._assert_signature_rejected(original, changed)

    def test_legacy_output_without_signature_is_rejected(self):
        path = Mock()
        path.exists.return_value = True
        path.read_text.return_value = json.dumps({"evaluation": {}, "results": []})
        with self.assertRaisesRegex(BenchmarkIntegrityError, "lack a resume signature"):
            load_existing_results(path, signature(self.cases), self.cases)

    def _assert_signature_rejected(self, saved, requested):
        path = Mock()
        path.exists.return_value = True
        path.read_text.return_value = json.dumps({
            "resume_signature": saved,
            "results": [result("V1", "CWE-89")],
        })
        with self.assertRaisesRegex(BenchmarkIntegrityError, "different.*signature"):
            load_existing_results(path, requested, self.cases)


if __name__ == "__main__":
    unittest.main()
