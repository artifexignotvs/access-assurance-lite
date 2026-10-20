from __future__ import annotations

import unittest
from unittest.mock import patch

from assurance_lite import benchmark


class BenchmarkTests(unittest.TestCase):
    def test_labeled_corpus_matches_classifier(self):
        report = benchmark.run_benchmark()
        self.assertTrue(report["synthetic"])
        self.assertEqual(report["case_count"], 118)
        self.assertEqual(report["matched_count"], report["case_count"])
        self.assertEqual(report["mismatch_count"], 0, report["mismatches"])
        self.assertEqual(report["false_verified_count"], 0)
        self.assertEqual(sum(report["groups"].values()), report["case_count"])
        self.assertEqual(len({item["id"] for item in report["results"]}), report["case_count"])
        self.assertEqual(set(report["groups"]), {
            "decision_matrix", "observation_time", "credential_expiry",
            "observation_order", "scope_binding", "semantic_consistency",
        })

    def test_oracle_reports_a_broken_always_verified_classifier(self):
        with patch.object(benchmark, "classify", return_value="VERIFIED"):
            report = benchmark.run_benchmark()
        expected_failures = sum(item["expected"] != "VERIFIED" for item in report["results"])
        self.assertGreater(expected_failures, 100)
        self.assertEqual(report["mismatch_count"], expected_failures)
        self.assertEqual(report["false_verified_count"], expected_failures)
        self.assertEqual(len(report["mismatches"]), expected_failures)

    def test_classifier_exception_is_an_explicit_mismatch(self):
        with patch.object(benchmark, "classify", side_effect=ValueError("internal details")):
            report = benchmark.run_benchmark()
        self.assertEqual(report["mismatch_count"], report["case_count"])
        self.assertEqual({item["actual"] for item in report["results"]}, {"ERROR"})
        self.assertNotIn("internal details", str(report))

    def test_synthetic_results_are_reproducible(self):
        self.assertEqual(benchmark.run_benchmark(), benchmark.run_benchmark())


if __name__ == "__main__":
    unittest.main()
