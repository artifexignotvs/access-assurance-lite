from __future__ import annotations

import csv
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from assurance_lite import lab
from assurance_lite.common import write_private


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.environment = os.environ.copy()
        self.environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        self.private_values = []

    def tearDown(self):
        self.temporary.cleanup()

    def run_cli(self, *arguments):
        result = subprocess.run(
            [sys.executable, "-m", "assurance_lite", *(str(argument) for argument in arguments)],
            env=self.environment, cwd=self.directory,
            capture_output=True, text=True, timeout=15,
        )
        for stream in (result.stdout, result.stderr):
            self.assertNotIn("Traceback", stream)
            for private in self.private_values:
                self.assertNotIn(private, stream)
        return result

    def configure(self, config):
        self.private_values.extend((config.subject_token, config.control_token))
        for filename, token in (("subject.token", config.subject_token), ("control.token", config.control_token)):
            path = self.directory / filename
            path.write_text(token)
            path.chmod(0o600)
        configuration = self.directory / "config.json"
        write_private(configuration, {
            "schema": "access-assurance-lite/config-v1",
            "subject": {"id": config.subject_id, "token_file": "subject.token"},
            "control": {"id": config.control_id, "token_file": "control.token"},
            "resources": [{"id": item.id, "url": item.url} for item in config.resources],
            "timeout_seconds": 1, "freshness_seconds": 30,
        })
        return configuration

    def establish(self, configuration):
        destination = self.directory / "baseline.json"
        result = self.run_cli("baseline", "--config", configuration, "--allow-http-loopback", "--out", destination, "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["state"], "READY")
        return destination

    def test_demo_inspection_and_csv_are_explicitly_historical(self):
        directory = self.directory / "demo"
        completed = self.run_cli("demo", "--directory", directory, "--json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertTrue(report["synthetic"])
        self.assertEqual(report["resource_count"], 2)
        artifact = directory / "denied.json"
        output_csv = self.directory / "review.csv"
        inspected = self.run_cli("inspect", artifact, "--csv", output_csv, "--json")
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        summary = json.loads(inspected.stdout)
        self.assertEqual(summary["currentness"], "HISTORICAL_ONLY")
        self.assertEqual(summary["recorded_state"], "VERIFIED")
        self.assertEqual(stat.S_IMODE(output_csv.stat().st_mode), 0o600)
        with output_csv.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["evidence_scope"] for row in rows}, {"HISTORICAL_ONLY"})
        human = self.run_cli("inspect", artifact)
        self.assertIn("Recorded result:", human.stdout)
        self.assertIn("HISTORICAL_ONLY", human.stdout)
        original = output_csv.read_bytes()
        collision = self.run_cli("inspect", artifact, "--csv", output_csv, "--json")
        self.assertEqual(collision.returncode, 4)
        self.assertEqual(output_csv.read_bytes(), original)

    def test_live_check_exit_codes_and_private_output(self):
        with lab._running_lab() as (laboratory, config):
            configuration = self.configure(config)
            baseline = self.establish(configuration)
            for phase, state, status in (("denied", "VERIFIED", 0), ("restored", "RESIDUAL", 2),
                                         ("outage", "UNKNOWN", 3), ("failed-control", "UNKNOWN", 3)):
                with self.subTest(phase=phase):
                    laboratory.set_phase(phase)
                    output = self.directory / (phase + ".json")
                    completed = self.run_cli("check", "--config", configuration, "--baseline", baseline,
                                             "--allow-http-loopback", "--out", output, "--json")
                    self.assertEqual(completed.returncode, status, completed.stderr)
                    self.assertEqual(json.loads(completed.stdout)["state"], state)
                    self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                    for private in self.private_values:
                        self.assertNotIn(private, output.read_text())

    def test_comparison_reports_only_changes_and_rejects_reversed_order(self):
        directory = self.directory / "demo"
        self.assertEqual(self.run_cli("demo", "--directory", directory, "--json").returncode, 0)
        before, after = directory / "denied.json", directory / "restored.json"
        comparison = self.run_cli("compare", before, after, "--json")
        self.assertEqual(comparison.returncode, 0, comparison.stderr)
        data = json.loads(comparison.stdout)
        self.assertEqual(data["currentness"], "HISTORICAL_ONLY")
        self.assertEqual(data["changes"], [{"resource_id": "synthetic-alpha", "before": "VERIFIED", "after": "RESIDUAL"}])
        reversed_result = self.run_cli("compare", after, before, "--json")
        self.assertEqual(reversed_result.returncode, 4)
        self.assertEqual(json.loads(reversed_result.stderr)["error"], "comparison_order_invalid")
        invalid_kind = self.run_cli("compare", directory / "baseline.json", after, "--json")
        self.assertEqual(invalid_kind.returncode, 4)
        self.assertEqual(json.loads(invalid_kind.stderr)["error"], "comparison_requires_checks")

    def test_comparison_rejects_different_laboratories(self):
        first, second = self.directory / "first", self.directory / "second"
        for directory in (first, second):
            self.assertEqual(self.run_cli("demo", "--directory", directory, "--json").returncode, 0)
        result = self.run_cli("compare", first / "denied.json", second / "denied.json", "--json")
        self.assertEqual(result.returncode, 4)
        self.assertEqual(json.loads(result.stderr)["error"], "comparison_scope_mismatch")

    def test_output_collisions_do_not_overwrite_evidence(self):
        with lab._running_lab() as (_, config):
            configuration = self.configure(config)
            baseline = self.establish(configuration)
            original = baseline.read_bytes()
            result = self.run_cli("baseline", "--config", configuration, "--allow-http-loopback",
                                  "--out", baseline, "--json")
            self.assertEqual(result.returncode, 4)
            self.assertEqual(json.loads(result.stderr)["error"], "output_exists_or_unwritable")
            self.assertEqual(baseline.read_bytes(), original)
        destination = self.directory / "existing"
        destination.mkdir()
        sentinel = destination / "sentinel"
        sentinel.write_text("preserved")
        for command in ("demo", "init"):
            with self.subTest(command=command):
                result = self.run_cli(command, "--directory", destination, "--json")
                self.assertEqual(result.returncode, 4)
                self.assertEqual(sentinel.read_text(), "preserved")

    def test_malformed_and_tampered_evidence_do_not_echo_input(self):
        marker = "synthetic-sensitive-marker-do-not-echo"
        self.private_values.append(marker)
        path = self.directory / "invalid.json"
        for content in ('{"hidden":"' + marker + '",', json.dumps({"secret": marker}), "[1,2,3]"):
            with self.subTest(content_type=content[:1]):
                path.write_text(content)
                result = self.run_cli("inspect", path, "--json")
                self.assertEqual(result.returncode, 4)
                self.assertEqual(result.stdout, "")
                self.assertIn("error", json.loads(result.stderr))
        directory = self.directory / "demo"
        self.assertEqual(self.run_cli("demo", "--directory", directory, "--json").returncode, 0)
        document = json.loads((directory / "denied.json").read_text())
        document["payload"]["state"] = "RESIDUAL"
        path.write_text(json.dumps(document))
        result = self.run_cli("inspect", path, "--json")
        self.assertEqual(result.returncode, 4)
        self.assertIn("error", json.loads(result.stderr))

    def test_http_requires_explicit_loopback_opt_in(self):
        with lab._running_lab() as (_, config):
            configuration = self.configure(config)
            result = self.run_cli("baseline", "--config", configuration,
                                  "--out", self.directory / "result.json", "--json")
        self.assertEqual(result.returncode, 4)
        self.assertEqual(json.loads(result.stderr)["error"], "https_required")
        self.assertFalse((self.directory / "result.json").exists())

    def test_invalid_credentials_are_redacted(self):
        with lab._running_lab() as (_, config):
            configuration = self.configure(config)
            (self.directory / "subject.token").write_text(config.subject_token + " invalid")
            result = self.run_cli("baseline", "--config", configuration, "--allow-http-loopback",
                                  "--out", self.directory / "result.json", "--json")
        self.assertEqual(result.returncode, 4)
        self.assertEqual(json.loads(result.stderr)["error"], "credential_invalid")

    def test_bounded_watch_streams_samples_and_preserves_artifacts(self):
        with lab._running_lab() as (laboratory, config):
            configuration = self.configure(config)
            baseline = self.establish(configuration)
            laboratory.set_phase("denied")
            output = self.directory / "watch"
            result = self.run_cli("watch", "--config", configuration, "--baseline", baseline,
                                  "--allow-http-loopback", "--directory", output,
                                  "--count", "2", "--interval", "0.1", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        samples = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([item["sequence"] for item in samples], [1, 2])
        self.assertEqual({item["state"] for item in samples}, {"VERIFIED"})
        self.assertEqual(len(list(output.iterdir())), 3)
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(summary["samples"], 2)
        self.assertEqual(summary["currentness"], "HISTORICAL_ONLY")

    def test_watch_rejects_invalid_limits_before_reading_configuration(self):
        for count, interval in (("0", "1"), ("721", "1"), ("2", "nan"), ("2", "inf"), ("720", "60")):
            with self.subTest(count=count, interval=interval):
                result = self.run_cli("watch", "--config", self.directory / "absent.json",
                                      "--baseline", self.directory / "absent-baseline.json",
                                      "--directory", self.directory / "watch",
                                      "--count", count, "--interval", interval, "--json")
                self.assertEqual(result.returncode, 4)
                self.assertEqual(json.loads(result.stderr)["error"], "watch_limits_exceeded")


if __name__ == "__main__":
    unittest.main()
