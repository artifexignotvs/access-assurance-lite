from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from assurance_lite.common import AssuranceError, Resource, RuntimeConfig, canonical, read_json, read_secret, write_private


class CommonBoundaryTests(unittest.TestCase):
    def test_runtime_config_repr_does_not_disclose_credentials(self):
        subject_token = "synthetic-subject-sensitive-credential"
        control_token = "synthetic-control-sensitive-credential"
        config = RuntimeConfig("subject", "control", subject_token, control_token,
                               (Resource("test", "https://example.invalid/probe"),))
        for value in (repr(config), str(config), json.dumps(config.scope())):
            self.assertNotIn(subject_token, value)
            self.assertNotIn(control_token, value)

    def test_json_limits_cannot_disable_bounded_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text("{}")
            for limit in (-1, 0, True, 1.0, 16 * 1024 * 1024 + 1, None):
                with self.subTest(limit=limit):
                    with self.assertRaisesRegex(AssuranceError, "invalid_document_limit"):
                        read_json(path, limit=limit)

    def test_json_size_duplicate_keys_and_invalid_numbers_are_rejected(self):
        invalid = (
            ('{"x":1,"x":2}', "duplicate_json_key"),
            ('{"x":NaN}', "invalid_json_number"),
            ('{"x":Infinity}', "invalid_json_number"),
            ('{"x":-Infinity}', "invalid_json_number"),
            ('{"x":1e9999}', "invalid_json_number"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for content, code in invalid:
                with self.subTest(content=content):
                    path.write_text(content)
                    with self.assertRaisesRegex(AssuranceError, code):
                        read_json(path)
            path.write_text(json.dumps({"data": "x" * 100}))
            with self.assertRaisesRegex(AssuranceError, "document_too_large"):
                read_json(path, limit=20)

    def test_json_regular_document_and_symlink_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text('{"value":12}')
            self.assertEqual(read_json(path), {"value": 12})
            alias = Path(directory) / "alias.json"
            alias.symlink_to(path)
            with self.assertRaises(AssuranceError):
                read_json(alias)
            with self.assertRaises(AssuranceError):
                read_json(directory)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires filesystem FIFO support")
    def test_json_fifo_returns_without_waiting_for_a_writer(self):
        code = (
            "import sys\n"
            "from assurance_lite.common import read_json, AssuranceError\n"
            "try:\n"
            "    read_json(sys.argv[1])\n"
            "except AssuranceError as exc:\n"
            "    print(exc.code)\n"
            "else:\n"
            "    raise SystemExit(9)\n"
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "document.fifo"
            os.mkfifo(fifo, 0o600)
            result = subprocess.run([sys.executable, "-c", code, str(fifo)],
                                    env=environment, capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "document_not_regular")
        self.assertEqual(result.stderr, "")

    def test_invalid_encoding_and_decoder_failure_have_safe_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(b"\xff\xfe\x80")
            with self.assertRaisesRegex(AssuranceError, "document_unreadable"):
                read_json(path)
            path.write_text("{}")
            with patch("assurance_lite.common.json.loads", side_effect=RecursionError("private decoder details")):
                with self.assertRaisesRegex(AssuranceError, "^document_unreadable$"):
                    read_json(path)

    def test_exclusive_private_write_preserves_existing_and_symlink_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            write_private(path, {"result": "first"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            original = path.read_bytes()
            with self.assertRaisesRegex(AssuranceError, "output_exists_or_unwritable"):
                write_private(path, {"result": "second"})
            self.assertEqual(path.read_bytes(), original)
            alias = Path(directory) / "alias.json"
            alias.symlink_to(path)
            with self.assertRaises(AssuranceError):
                write_private(alias, {"result": "third"})
            self.assertEqual(path.read_bytes(), original)

    def test_invalid_json_value_creates_no_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            with self.assertRaisesRegex(AssuranceError, "invalid_json_value"):
                write_private(path, {"value": float("nan")})
            self.assertFalse(path.exists())

    def test_secret_requires_private_regular_file_and_rejects_symlink(self):
        token = "synthetic-only-test-credential-0123456789"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credential"
            path.write_text(token + "\n")
            path.chmod(0o600)
            self.assertEqual(read_secret(path), token)
            path.chmod(0o644)
            with self.assertRaisesRegex(AssuranceError, "credential_file_not_private"):
                read_secret(path)
            path.chmod(0o600)
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(AssuranceError):
                read_secret(alias)
            if hasattr(os, "mkfifo"):
                fifo = Path(directory) / "credential.fifo"
                os.mkfifo(fifo, 0o600)
                with self.assertRaisesRegex(AssuranceError, "credential_file_not_private"):
                    read_secret(fifo)

    def test_canonical_encoding_is_stable_and_rejects_cycles(self):
        self.assertEqual(canonical({"z": 2, "a": 1}), canonical({"a": 1, "z": 2}))
        cycle = []
        cycle.append(cycle)
        with self.assertRaisesRegex(AssuranceError, "invalid_json_value"):
            canonical(cycle)


if __name__ == "__main__":
    unittest.main()
