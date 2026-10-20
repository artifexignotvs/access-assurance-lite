"""Configuration and credential boundary tests."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from assurance_lite.common import AssuranceError
from assurance_lite.config import load_config, validate_resource_url


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        for name, token in (("subject.token", "synthetic-subject-token"),
                            ("control.token", "synthetic-control-token")):
            path = self.base / name
            path.write_text(token + "\n")
            path.chmod(0o600)
        self.path = self.base / "config.json"
        self.data = {"schema": "access-assurance-lite/config-v1",
                     "subject": {"id": "subject", "token_file": "subject.token"},
                     "control": {"id": "control", "token_file": "control.token"},
                     "resources": [{"id": "application", "url": "https://example.invalid/probe"}]}

    def load(self, **kwargs):
        self.path.write_text(json.dumps(self.data))
        return load_config(self.path, **kwargs)

    def rejects(self, **kwargs):
        with self.assertRaises(AssuranceError) as error:
            self.load(**kwargs)
        self.assertNotIn(str(self.base), str(error.exception))
        self.assertNotIn("synthetic-subject-token", str(error.exception))

    def test_relative_private_credentials_and_defaults(self):
        config = self.load()
        self.assertEqual(config.subject_token, "synthetic-subject-token")
        self.assertEqual(config.resources[0].id, "application")
        self.assertEqual(config.timeout_seconds, 3)
        self.assertFalse(config.allow_http_loopback)

    def test_unknown_root_and_nested_fields(self):
        for container in (self.data, self.data["subject"], self.data["resources"][0]):
            container["surprise"] = True
            self.rejects()
            del container["surprise"]

    def test_duplicate_json_keys(self):
        self.path.write_text('{"schema": 1, "schema": 2}')
        with self.assertRaises(AssuranceError):
            load_config(self.path)

    def test_bad_schema(self):
        self.data["schema"] = "future-version"
        self.rejects()

    def test_numeric_boundaries(self):
        cases = {"timeout_seconds": [False, 0, 30.1, "3", float("nan"), 10**400],
                 "max_response_bytes": [True, 0, 65537, 1024.0],
                 "freshness_seconds": [True, 0, 301, 30.0]}
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=str(value)[:20]):
                    self.data[key] = value
                    self.rejects()
            del self.data[key]
        self.data.update(timeout_seconds=.1, max_response_bytes=1024, freshness_seconds=1)
        self.assertEqual(self.load().freshness_seconds, 1)

    def test_distinct_ids_and_tokens_required(self):
        self.data["control"]["id"] = "subject"
        self.rejects()
        self.data["control"]["id"] = "control"
        (self.base / "control.token").write_text("synthetic-subject-token")
        self.rejects()

    def test_public_secret_file_rejected(self):
        (self.base / "subject.token").chmod(0o644)
        self.rejects()

    def test_symlink_secret_rejected(self):
        target = self.base / "linked.token"
        target.symlink_to(self.base / "subject.token")
        self.data["subject"]["token_file"] = target.name
        self.rejects()

    def test_nonregular_credential_file_rejected(self):
        fifo = self.base / "pipe.token"
        os.mkfifo(fifo, 0o600)
        self.data["subject"]["token_file"] = fifo.name
        self.rejects()

    def test_tokens_cannot_inject_headers(self):
        for value in ("short", "synthetic-token\r\nX-Injection: yes", "a" * 8193, "nonascii-\u00e9-token"):
            (self.base / "subject.token").write_text(value)
            self.rejects()

    def test_unsafe_identifiers(self):
        for value in ("", "a" * 129, "some id", "\x1b[31m", "\u00e9", 12):
            self.data["subject"]["id"] = value
            self.rejects()

    def test_http_requires_opt_in_and_literal_loopback(self):
        self.data["resources"][0]["url"] = "http://127.0.0.1:5199/probe"
        self.rejects()
        self.assertTrue(self.load(allow_http_loopback=True).allow_http_loopback)
        self.data["resources"][0]["url"] = "http://[::1]:5199/probe"
        self.assertTrue(self.load(allow_http_loopback=True).allow_http_loopback)
        for url in ("http://localhost/probe", "http://127.1/probe", "http://192.0.2.1/probe",
                    "http://[::ffff:127.0.0.1]/probe"):
            self.data["resources"][0]["url"] = url
            self.rejects(allow_http_loopback=True)

    def test_urls_reject_credentials_queries_and_ambiguous_forms(self):
        for url in ("https://name:password@example.invalid/probe", "https://example.invalid/?token=x",
                    "https://example.invalid/#secret", "https://example.invalid/?",
                    "ftp://example.invalid/probe", "https://example.invalid:0/probe",
                    "https://example.invalid:65536/probe", "https://example.invalid/with space",
                    "https://example.invalid/\r\nheader", "https://example.invalid\\@other.invalid/",
                    "https://[::1%lo]/probe", "https://bad_host.invalid/probe"):
            with self.subTest(url=repr(url)):
                with self.assertRaises(AssuranceError):
                    validate_resource_url(url, allow_http_loopback=True)

    def test_duplicate_resources_and_scope_limit(self):
        item = self.data["resources"][0]
        self.data["resources"].append(dict(item, id="second"))
        self.rejects()
        self.data["resources"][1]["url"] = "https://EXAMPLE.invalid:443/probe"
        self.rejects()
        self.data["resources"] = []
        self.rejects()
        self.data["resources"] = [{"id": f"r{i}", "url": f"https://example.invalid/{i}"} for i in range(17)]
        self.rejects()

    def test_oversized_document(self):
        self.path.write_text(" " * 65537)
        with self.assertRaises(AssuranceError):
            load_config(self.path)


if __name__ == "__main__":
    unittest.main()
