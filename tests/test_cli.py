from __future__ import annotations

import csv
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from assurance_lite import cli, engine, lab
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
        self.assertEqual(summary["completion"], "COMPLETE")
        self.assertIsNone(summary["error"])
        self.assertEqual(summary["currentness"], "HISTORICAL_ONLY")
        self.assertEqual(summary["transitions"], [])
        self.assertEqual(summary["first_verified_elapsed_seconds"], samples[0]["elapsed_seconds"])
        self.assertLessEqual(samples[-1]["elapsed_seconds"], summary["elapsed_seconds"])

    def test_watch_rejects_invalid_limits_before_reading_configuration(self):
        for count, interval in (("0", "1"), ("721", "1"), ("2", "nan"), ("2", "inf"), ("720", "60")):
            with self.subTest(count=count, interval=interval):
                result = self.run_cli("watch", "--config", self.directory / "absent.json",
                                      "--baseline", self.directory / "absent-baseline.json",
                                      "--directory", self.directory / "watch",
                                      "--count", count, "--interval", interval, "--json")
                self.assertEqual(result.returncode, 4)
                self.assertEqual(json.loads(result.stderr)["error"], "watch_limits_exceeded")

    def test_watch_measures_live_transitions_from_watch_start(self):
        with lab._running_lab() as (laboratory, config):
            configuration = self.configure(config)
            baseline = self.establish(configuration)
            laboratory.set_phase("restored")
            output = self.directory / "transition-watch"
            arguments = cli.parser().parse_args([
                "watch", "--config", str(configuration), "--baseline", str(baseline),
                "--allow-http-loopback", "--directory", str(output),
                "--count", "4", "--interval", "0.1", "--json",
            ])
            next_phases = iter(("outage", "denied", "restored"))

            def next_sample(_interval):
                laboratory.set_phase(next(next_phases))

            captured = io.StringIO()
            with patch("assurance_lite.cli.time.sleep", side_effect=next_sample):
                with redirect_stdout(captured):
                    status = cli._watch(arguments)
        self.assertEqual(status, 2)
        samples = [json.loads(line) for line in captured.getvalue().splitlines()]
        self.assertEqual([sample["state"] for sample in samples],
                         ["RESIDUAL", "UNKNOWN", "VERIFIED", "RESIDUAL"])
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(summary["timing_reference"], "WATCH_START_NOT_ADMINISTRATIVE_ACTION")
        self.assertEqual(summary["residual_samples"], 2)
        self.assertEqual(summary["unknown_samples"], 1)
        transitions = summary["transitions"]
        self.assertEqual([(item["sequence"], item["before"], item["after"]) for item in transitions], [
            (2, "RESIDUAL", "UNKNOWN"),
            (3, "UNKNOWN", "VERIFIED"),
            (4, "VERIFIED", "RESIDUAL"),
        ])
        first_verified = summary["first_verified_elapsed_seconds"]
        verified_transition = next(item for item in transitions if item["after"] == "VERIFIED")
        self.assertEqual(first_verified, verified_transition["elapsed_seconds"])
        self.assertGreaterEqual(first_verified, 0)
        self.assertLessEqual(first_verified, summary["elapsed_seconds"])
        self.assertEqual([item["elapsed_seconds"] for item in transitions],
                         sorted(item["elapsed_seconds"] for item in transitions))
        for secret in self.private_values:
            self.assertNotIn(secret, captured.getvalue())
            self.assertNotIn(secret, json.dumps(summary))


    def interrupted_watch(self, failure, *, expiry=False, fail_summary=False):
        with lab._running_lab() as (laboratory, config):
            configuration = self.configure(config)
            baseline = self.establish(configuration)
            laboratory.set_phase("denied")
            output = self.directory / "partial-watch"
            arguments = ["watch", "--config", str(configuration), "--baseline", str(baseline),
                         "--allow-http-loopback", "--directory", str(output),
                         "--count", "2", "--interval", "0.1", "--json"]
            expires = json.loads(baseline.read_text())["payload"]["expires_at"]
            original_check = engine.check
            calls = 0

            def check_next(*args):
                nonlocal calls
                calls += 1
                if expiry and calls == 2:
                    with patch("assurance_lite.engine.utc_now", return_value=expires):
                        return original_check(*args)
                return original_check(*args)

            original_write = cli.write_private

            def save(path, value):
                if fail_summary and Path(path).name == "summary.json":
                    raise OSError("synthetic-private-storage-detail")
                return original_write(path, value)

            captured, errors = io.StringIO(), io.StringIO()
            with patch("assurance_lite.engine.check", side_effect=check_next):
                with patch("assurance_lite.cli.time.sleep", side_effect=failure):
                    with patch("assurance_lite.cli.write_private", side_effect=save):
                        with redirect_stdout(captured), redirect_stderr(errors):
                            status = cli.main(arguments)
        self.assertTrue((output / "check-0001.json").exists())
        self.assertFalse((output / "check-0002.json").exists())
        recorded = json.loads((output / "check-0001.json").read_text())
        self.assertEqual(recorded["payload"]["state"], "VERIFIED")
        for secret in self.private_values + ["synthetic-private-storage-detail"]:
            self.assertNotIn(secret, captured.getvalue() + errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        summary = None if fail_summary else json.loads((output / "summary.json").read_text())
        if summary is not None:
            self.assertEqual(summary["samples"], 1)
            self.assertEqual(summary["requested_samples"], 2)
            self.assertEqual(summary["last_recorded_state"], "VERIFIED")
            self.assertEqual(summary["last_reported_state"], "VERIFIED")
            self.assertEqual(summary["currentness"], "HISTORICAL_ONLY")
            self.assertIsNotNone(summary["first_verified_elapsed_seconds"])
            self.assertEqual(stat.S_IMODE((output / "summary.json").stat().st_mode), 0o600)
            for secret in self.private_values:
                self.assertNotIn(secret, json.dumps(summary))
        return status, json.loads(errors.getvalue()), summary

    def test_watch_preserves_partial_summary_when_baseline_expires(self):
        status, error, summary = self.interrupted_watch(None, expiry=True)
        self.assertEqual(status, 4)
        self.assertEqual(error["error"], "baseline_expired_or_future")
        self.assertEqual(summary["completion"], "FAILED")
        self.assertEqual(summary["error"], "baseline_expired_or_future")

    def test_watch_preserves_partial_summary_on_operator_interruption(self):
        status, error, summary = self.interrupted_watch(KeyboardInterrupt())
        self.assertEqual(status, 130)
        self.assertEqual(error["error"], "interrupted")
        self.assertEqual(summary["completion"], "INTERRUPTED")
        self.assertEqual(summary["error"], "interrupted")

    def test_watch_redacts_unexpected_failure_in_partial_summary(self):
        marker = "synthetic-sensitive-runtime-detail"
        self.private_values.append(marker)
        status, error, summary = self.interrupted_watch(RuntimeError(marker))
        self.assertEqual(status, 4)
        self.assertEqual(error["error"], "operation_failed")
        self.assertEqual(summary["completion"], "FAILED")
        self.assertEqual(summary["error"], "operation_failed")

    def test_watch_summary_failure_does_not_mask_operator_interruption(self):
        status, error, _ = self.interrupted_watch(KeyboardInterrupt(), fail_summary=True)
        self.assertEqual(status, 130)
        self.assertEqual(error["error"], "interrupted")


    def test_watch_scheduling_cutoff_is_incomplete_and_never_successful(self):
        with lab._running_lab() as (laboratory, config):
            configuration = self.configure(config)
            baseline = self.establish(configuration)
            laboratory.set_phase("denied")
            output = self.directory / "limited-watch"
            arguments = ["watch", "--config", str(configuration), "--baseline", str(baseline),
                         "--allow-http-loopback", "--directory", str(output),
                         "--count", "2", "--interval", "0.1", "--json"]
            clock = {"elapsed": 0.0}

            def scheduling_pause(_interval):
                clock["elapsed"] = 3601.0

            isolated_time = SimpleNamespace(monotonic=lambda: clock["elapsed"], sleep=scheduling_pause)
            captured, errors = io.StringIO(), io.StringIO()
            with patch.object(cli, "time", isolated_time):
                with redirect_stdout(captured), redirect_stderr(errors):
                    status = cli.main(arguments)
        self.assertEqual(status, 4)
        self.assertEqual(json.loads(errors.getvalue())["error"], "watch_time_limit_reached")
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(summary["completion"], "LIMIT_REACHED")
        self.assertEqual(summary["error"], "watch_time_limit_reached")
        self.assertEqual(summary["samples"], 1)
        self.assertEqual(summary["requested_samples"], 2)
        self.assertEqual(summary["last_recorded_state"], "VERIFIED")
        self.assertTrue((output / "check-0001.json").exists())
        self.assertFalse((output / "check-0002.json").exists())


if __name__ == "__main__":
    unittest.main()
