from __future__ import annotations

import json
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from assurance_lite import evidence, lab, transport
from assurance_lite.common import AssuranceError


class LaboratoryTests(unittest.TestCase):
    def assert_listener_closed(self, url):
        parsed = urlsplit(url)
        with socket.socket() as client:
            client.settimeout(0.3)
            self.assertNotEqual(client.connect_ex((parsed.hostname, parsed.port)), 0)

    def test_real_http_sequence_private_artifacts_and_cleanup(self):
        observed_configs = []
        actual_probe = transport.probe

        def record_probe(config, resource, role):
            observed_configs.append(config)
            return actual_probe(config, resource, role)

        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "demo"
            with patch.object(transport, "probe", side_effect=record_probe):
                result = lab.run_demo(output)
            self.assertTrue(result["synthetic"])
            self.assertEqual(len(observed_configs), 36)
            self.assertEqual([stage["state"] for stage in result["stages"]],
                             ["READY", "VERIFIED", "RESIDUAL", "UNKNOWN", "UNKNOWN", "VERIFIED"])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(len(list(output.iterdir())), 7)
            config = observed_configs[0]
            self.assertNotEqual(config.subject_token, config.control_token)
            for artifact in output.iterdir():
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
                content = artifact.read_text()
                self.assertNotIn(config.subject_token, content)
                self.assertNotIn(config.control_token, content)
                if artifact.name != "summary.json":
                    verified = evidence.verify(json.loads(content))
                    self.assertIn(verified["state"], {"READY", "VERIFIED", "RESIDUAL", "UNKNOWN"})
            restored = json.loads((output / "restored.json").read_text())["payload"]
            self.assertEqual([item["state"] for item in restored["results"]], ["RESIDUAL", "VERIFIED"])
            failed = json.loads((output / "failed-control.json").read_text())["payload"]
            self.assertEqual(failed["results"][0]["subject"]["decision"], "DENY")
            self.assertEqual(failed["results"][0]["control_before"]["decision"], "DENY")
            self.assert_listener_closed(config.resources[0].url)

    def test_engine_failure_still_closes_owned_listener(self):
        configurations = []

        def fail(config):
            configurations.append(config)
            raise AssuranceError("synthetic_failure")

        with tempfile.TemporaryDirectory() as parent:
            with patch.object(lab.engine, "baseline", side_effect=fail):
                with self.assertRaisesRegex(AssuranceError, "synthetic_failure"):
                    lab.run_demo(Path(parent) / "demo")
            self.assert_listener_closed(configurations[0].resources[0].url)

    def test_artifact_failure_still_closes_owned_listener(self):
        configurations = []
        actual_baseline = lab.engine.baseline

        def record(config):
            configurations.append(config)
            return actual_baseline(config)

        with tempfile.TemporaryDirectory() as parent:
            with patch.object(lab.engine, "baseline", side_effect=record):
                with patch.object(lab, "write_private", side_effect=AssuranceError("synthetic_write_failure")):
                    with self.assertRaisesRegex(AssuranceError, "synthetic_write_failure"):
                        lab.run_demo(Path(parent) / "demo")
            self.assert_listener_closed(configurations[0].resources[0].url)

    def test_existing_destination_is_never_reused(self):
        with tempfile.TemporaryDirectory() as parent:
            destination = Path(parent) / "existing"
            destination.mkdir()
            sentinel = destination / "sentinel"
            sentinel.write_text("keep")
            with patch.object(lab.engine, "baseline") as baseline:
                with self.assertRaisesRegex(AssuranceError, "demo_output_exists_or_unwritable"):
                    lab.run_demo(destination)
                baseline.assert_not_called()
            self.assertEqual(sentinel.read_text(), "keep")

    def test_symlink_destination_is_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            target = Path(parent) / "target"
            target.mkdir()
            alias = Path(parent) / "alias"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaises(AssuranceError):
                lab.run_demo(alias)
            self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
