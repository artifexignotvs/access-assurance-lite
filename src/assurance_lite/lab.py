"""An isolated, synthetic resource exercise. Experimentum intra fines."""

from __future__ import annotations

import secrets
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

from . import engine
from .common import AssuranceError, Resource, RuntimeConfig, canonical, write_private


class _Laboratory:
    """All credentials and mutable resource state live only in this process."""

    def __init__(self) -> None:
        self.subject_token = secrets.token_urlsafe(32)
        self.control_token = secrets.token_urlsafe(32)
        while self.control_token == self.subject_token:
            self.control_token = secrets.token_urlsafe(32)
        self.expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        self.phase = "baseline"
        self.lock = threading.Lock()

    def set_phase(self, phase: str) -> None:
        with self.lock:
            self.phase = phase

    def handler(self) -> type[BaseHTTPRequestHandler]:
        laboratory = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                self.request.settimeout(2.0)
                super().setup()

            def log_message(self, _format: str, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                routes = {"/alpha": "synthetic-alpha", "/beta": "synthetic-beta"}
                resource_id = routes.get(self.path)
                if resource_id is None:
                    self.reply(404, {"error": "unknown_resource"})
                    return
                with laboratory.lock:
                    phase = laboratory.phase
                if phase == "outage":
                    self.reply(503, {"error": "synthetic_outage"})
                    return
                authorization = self.headers.get("Authorization", "")
                if authorization == "Bearer " + laboratory.subject_token:
                    subject_id = "synthetic-subject"
                    role = "subject"
                elif authorization == "Bearer " + laboratory.control_token:
                    subject_id = "synthetic-control"
                    role = "control"
                else:
                    self.reply(401, {"error": "invalid_credential"})
                    return
                allowed = (
                    (role == "control" and phase != "failed-control")
                    or phase == "baseline"
                    or (role == "subject" and phase == "restored" and resource_id == "synthetic-alpha")
                )
                self.reply(200 if allowed else 403, {
                    "schema": "access-assurance-probe/v1",
                    "challenge": self.headers.get("X-Assurance-Challenge", ""),
                    "subject_id": subject_id,
                    "resource_id": resource_id,
                    "decision": "ALLOW" if allowed else "DENY",
                    "credential_valid": True,
                    "reason": "ACCESS_ALLOWED" if allowed else "POLICY_DENIED",
                    "credential_expires_at": laboratory.expires_at,
                })

            def reply(self, status: int, payload: dict) -> None:
                body = canonical(payload)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

        return Handler


@contextmanager
def _running_lab() -> Iterator[tuple[_Laboratory, RuntimeConfig]]:
    laboratory = _Laboratory()
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), laboratory.handler())
    except OSError:
        raise AssuranceError("demo_listener_unavailable") from None
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    started = False
    try:
        worker.start()
        started = True
        port = server.server_address[1]
        config = RuntimeConfig(
            subject_id="synthetic-subject", control_id="synthetic-control",
            subject_token=laboratory.subject_token, control_token=laboratory.control_token,
            resources=(
                Resource("synthetic-alpha", f"http://127.0.0.1:{port}/alpha"),
                Resource("synthetic-beta", f"http://127.0.0.1:{port}/beta"),
            ),
            timeout_seconds=2.0, freshness_seconds=30, allow_http_loopback=True,
        )
        yield laboratory, config
    finally:
        if started:
            server.shutdown()
        server.server_close()
        if started:
            worker.join(timeout=3.0)


def run_demo(output_directory: str | Path) -> dict:
    """Create new private artifacts from actual HTTP probes of synthetic resources."""
    destination = Path(output_directory)
    try:
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError:
        raise AssuranceError("demo_output_exists_or_unwritable") from None
    stages = []
    with _running_lab() as (laboratory, config):
        baseline_document = engine.baseline(config)
        write_private(destination / "baseline.json", baseline_document)
        stages.append({"stage": "baseline", "state": baseline_document["payload"]["state"], "artifact": "baseline.json"})
        for phase in ("denied", "restored", "outage", "failed-control", "recovered"):
            laboratory.set_phase(phase)
            document = engine.check(config, baseline_document)
            filename = phase + ".json"
            write_private(destination / filename, document)
            stages.append({"stage": phase, "state": document["payload"]["state"], "artifact": filename})
    summary = {
        "schema": "access-assurance-lite/demo-v1",
        "synthetic": True,
        "transport": "real HTTP requests to an owned ephemeral loopback listener",
        "resource_count": 2,
        "stages": stages,
        "limitations": [
            "Synthetic cooperating resources; no external identity provider or production system is tested.",
            "Only the declared identities, credentials, routes and observation times are covered.",
            "The evidence is historical and hashed, not signed or externally authenticated.",
            "Generated bearer credentials exist only in memory and the listener is stopped before return.",
        ],
    }
    write_private(destination / "summary.json", summary)
    return summary
