"""Real socket protocol tests, including false-assurance boundaries."""

import json
import os
import ssl
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from assurance_lite.common import Resource, RuntimeConfig
from assurance_lite.transport import probe

_SUBJECT = "synthetic-subject-token"
_CONTROL = "synthetic-control-token"


class ProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        server = self.server
        server.requests.append(dict(self.headers))
        kind = server.scenario
        if kind == "slow_headers":
            try:
                for chunk in (b"HTTP/1.1 200 OK\r\n", b"Content-Type: application/json\r\n", b"\r\n"):
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    time.sleep(.12)
            except OSError:
                pass
            return
        if kind == "timeout":
            time.sleep(.3)
        identity = "subject" if self.headers.get("Authorization") == "Bearer " + _SUBJECT else "control"
        expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
        status = 200
        data = {"schema": "access-assurance-probe/v1",
                "challenge": self.headers.get("X-Assurance-Challenge"),
                "subject_id": identity, "resource_id": "application", "decision": "ALLOW",
                "reason": "ACCESS_ALLOWED", "credential_valid": True,
                "credential_expires_at": expiry.isoformat().replace("+00:00", "Z")}
        headers = {"Content-Type": "application/json"}
        if kind == "denied":
            status = 403
            data.update(decision="DENY", reason="POLICY_DENIED")
        elif kind == "invalid_credential":
            status = 401
            data.update(decision="DENY", reason="CREDENTIAL_INVALID", credential_valid=False)
        elif kind == "expired":
            data["credential_expires_at"] = "2000-01-01T00:00:00Z"
        elif kind == "naive_expiry":
            data["credential_expires_at"] = "2099-01-01T00:00:00"
        elif kind == "offset_expiry":
            data["credential_expires_at"] = "2099-01-01T00:00:00+02:00"
        elif kind == "bad_timestamp":
            data["credential_expires_at"] = "2099-02-31T00:00:00Z"
        elif kind == "wrong_status":
            status = 403
        elif kind == "invalid_validity":
            data["credential_valid"] = 1
        elif kind == "wrong_reason":
            data["reason"] = "reflected-secret-" + _SUBJECT
        elif kind == "missing_field":
            del data["reason"]
        elif kind == "extra_field":
            data["debug"] = _SUBJECT
        elif kind == "wrong_challenge":
            data["challenge"] = "stale-challenge"
        elif kind == "wrong_identity":
            data["subject_id"] = "someone-else"
        elif kind == "wrong_resource":
            data["resource_id"] = "other"
        elif kind == "wrong_schema":
            data["schema"] = "wrong"
        elif kind == "compressed":
            headers["Content-Encoding"] = "gzip"
        elif kind == "wrong_type":
            headers["Content-Type"] = "text/plain"
        elif kind == "redirect":
            status = 302
            headers["Location"] = f"http://127.0.0.1:{server.server_port}/credential-trap"
        elif kind == "server_error":
            status = 500
        raw = json.dumps(data).encode()
        if kind == "oversized":
            raw += b" " * 2000
        elif kind == "duplicate_key":
            raw = raw[:-1] + b', "decision": "ALLOW"}'
        elif kind == "non_json":
            raw = b"<html>" + _SUBJECT.encode() + b"</html>"
        elif kind == "not_object":
            raw = b"[]"
        elif kind == "nonfinite":
            raw = raw.replace(b'true', b'NaN')
        try:
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            if kind == "duplicate_length":
                self.send_header("Content-Length", len(raw))
            if kind != "unframed_oversize":
                self.send_header("Content-Length", len(raw) + (1 if kind == "truncated" else 0))
            self.end_headers()
            if kind == "slow_body":
                for offset in range(0, len(raw), 20):
                    self.wfile.write(raw[offset:offset + 20])
                    self.wfile.flush()
                    time.sleep(.04)
            else:
                self.wfile.write(raw + (b" " * 2000 if kind == "unframed_oversize" else b""))
        except OSError:
            pass


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=2)

    def setUp(self):
        self.server.scenario = "allowed"
        self.server.requests = []
        self.resource = Resource("application", f"http://127.0.0.1:{self.server.server_port}/probe")
        self.config = RuntimeConfig("subject", "control", _SUBJECT, _CONTROL,
                                    (self.resource,), .5, 1024, 30, True)

    def run_probe(self, scenario="allowed", role="subject"):
        self.server.scenario = scenario
        result = probe(self.config, self.resource, role)
        self.assertEqual(set(result), {"decision", "reason", "credential_valid", "credential_expires_at",
                                      "observed_at", "duration_ms", "subject_id", "resource_id"})
        self.assertNotIn(_SUBJECT, json.dumps(result))
        self.assertNotIn(_CONTROL, json.dumps(result))
        self.assertIsInstance(result["duration_ms"], int)
        self.assertGreaterEqual(result["duration_ms"], 0)
        return result

    def test_real_allow_and_control_identity(self):
        result = self.run_probe()
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["credential_valid"])
        self.assertTrue(result["credential_expires_at"].endswith("Z"))
        self.assertEqual(self.run_probe(role="control")["subject_id"], "control")
        request = self.server.requests[0]
        self.assertEqual(request["Cache-Control"], "no-store")
        self.assertEqual(request["Accept-Encoding"], "identity")
        self.assertNotEqual(request["X-Assurance-Challenge"], self.server.requests[1]["X-Assurance-Challenge"])

    def test_explicit_valid_denial(self):
        result = self.run_probe("denied")
        self.assertEqual((result["decision"], result["reason"], result["credential_valid"]),
                         ("DENY", "POLICY_DENIED", True))

    def test_invalid_credential_is_not_valid_policy_denial(self):
        result = self.run_probe("invalid_credential")
        self.assertEqual(result["decision"], "DENY")
        self.assertFalse(result["credential_valid"])
        self.assertEqual(result["reason"], "CREDENTIAL_INVALID")

    def test_protocol_mismatches_never_become_denials(self):
        for scenario in ("wrong_status", "wrong_reason", "wrong_challenge", "wrong_identity",
                         "wrong_resource", "wrong_schema", "server_error"):
            with self.subTest(scenario=scenario):
                result = self.run_probe(scenario)
                self.assertEqual(result["decision"], "UNKNOWN")
                self.assertEqual(result["reason"], "PROTOCOL_MISMATCH")

    def test_malformed_data_and_headers_fail_closed(self):
        for scenario in ("invalid_validity", "missing_field", "extra_field", "compressed", "wrong_type",
                         "duplicate_key", "duplicate_length", "non_json", "not_object", "nonfinite",
                         "naive_expiry", "offset_expiry", "bad_timestamp", "truncated"):
            with self.subTest(scenario=scenario):
                result = self.run_probe(scenario)
                self.assertEqual(result["decision"], "UNKNOWN")
                self.assertIn(result["reason"], ("INVALID_RESPONSE", "NETWORK_ERROR"))
                self.assertIsNone(result["credential_expires_at"])

    def test_expired_validity_rejected(self):
        self.assertEqual(self.run_probe("expired")["reason"], "CREDENTIAL_EXPIRED")

    def test_redirect_does_not_forward_credentials(self):
        self.assertEqual(self.run_probe("redirect")["reason"], "REDIRECT_REJECTED")
        self.assertEqual(len(self.server.requests), 1)

    def test_size_limit_with_and_without_declared_length(self):
        for scenario in ("oversized", "unframed_oversize"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.run_probe(scenario)["reason"], "RESPONSE_TOO_LARGE")

    def test_timeout_and_slow_streams(self):
        self.config = replace(self.config, timeout_seconds=.15)
        for scenario in ("timeout", "slow_body", "slow_headers"):
            with self.subTest(scenario=scenario):
                started = time.monotonic()
                self.assertEqual(self.run_probe(scenario)["reason"], "TIMEOUT")
                self.assertLess(time.monotonic() - started, .7)

    def test_proxy_environment_ignored(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "http_proxy": "http://127.0.0.1:1",
                                     "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": "", "no_proxy": ""}):
            self.assertEqual(self.run_probe()["decision"], "ALLOW")

    def test_invalid_runtime_configuration_never_connects(self):
        with patch("assurance_lite.transport.http.client.HTTPConnection") as connection:
            self.config = replace(self.config, allow_http_loopback=False)
            self.assertEqual(self.run_probe()["reason"], "INVALID_CONFIGURATION")
            connection.assert_not_called()
        self.config = replace(self.config, allow_http_loopback=True, subject_token="bad\r\nheader")
        self.assertEqual(self.run_probe()["reason"], "INVALID_CONFIGURATION")

    def test_raw_connection_error_is_suppressed(self):
        with patch("assurance_lite.transport.http.client.HTTPConnection.connect",
                   side_effect=OSError("connection leaked " + _SUBJECT)):
            self.assertEqual(self.run_probe()["reason"], "NETWORK_ERROR")

    def test_tls_verification_enabled_and_errors_suppressed(self):
        self.resource = Resource("application", "https://example.invalid/probe")
        self.config = replace(self.config, resources=(self.resource,), allow_http_loopback=False)
        with patch("assurance_lite.transport.http.client.HTTPSConnection") as connection:
            connection.return_value.connect.side_effect = ssl.SSLError("untrusted " + _SUBJECT)
            self.assertEqual(self.run_probe()["reason"], "TLS_ERROR")
            context = connection.call_args.kwargs["context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)


if __name__ == "__main__":
    unittest.main()
