"""Bounded cooperating-resource probes. Dubium non est negatio."""

from __future__ import annotations

import http.client
import json
import math
import re
import secrets
import socket
import ssl
import threading
import time
from datetime import datetime, timezone

from .common import AssuranceError, Resource, RuntimeConfig, parse_time, utc_now
from .config import valid_identifier, validate_resource_url

_FIELDS = {"schema", "challenge", "subject_id", "resource_id", "decision",
           "reason", "credential_valid", "credential_expires_at"}
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")


class _Failure(Exception):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _Failure("INVALID_RESPONSE")
        result[key] = value
    return result


def _parse(raw, status, challenge, subject_id, resource_id):
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise _Failure("INVALID_RESPONSE") from None
    if not isinstance(doc, dict) or set(doc) != _FIELDS:
        raise _Failure("INVALID_RESPONSE")
    if (doc["schema"] != "access-assurance-probe/v1" or doc["challenge"] != challenge
            or doc["subject_id"] != subject_id or doc["resource_id"] != resource_id):
        raise _Failure("PROTOCOL_MISMATCH")
    decision, reason, valid = doc["decision"], doc["reason"], doc["credential_valid"]
    if type(valid) is not bool:
        raise _Failure("INVALID_RESPONSE")
    if not ((decision == "ALLOW" and reason == "ACCESS_ALLOWED" and valid and status == 200)
            or (decision == "DENY" and reason == "POLICY_DENIED" and valid and status == 403)
            or (decision == "DENY" and reason == "CREDENTIAL_INVALID" and not valid
                and status in (401, 403))):
        raise _Failure("PROTOCOL_MISMATCH")
    expiry = doc["credential_expires_at"]
    if not isinstance(expiry, str) or not _TIMESTAMP.fullmatch(expiry):
        raise _Failure("INVALID_RESPONSE")
    try:
        expires = parse_time(expiry)
    except AssuranceError:
        raise _Failure("INVALID_RESPONSE") from None
    if valid and expires <= datetime.now(timezone.utc):
        raise _Failure("CREDENTIAL_EXPIRED")
    return {"decision": decision, "reason": reason, "credential_valid": valid,
            "credential_expires_at": expires.isoformat(timespec="microseconds").replace("+00:00", "Z")}


def _validate(config, resource, role):
    if (not isinstance(config, RuntimeConfig) or not isinstance(resource, Resource)
            or role not in ("subject", "control") or resource not in config.resources
            or not all(valid_identifier(v) for v in
                       (config.subject_id, config.control_id, resource.id))
            or config.subject_id == config.control_id or config.subject_token == config.control_token
            or type(config.timeout_seconds) not in (int, float)
            or not 0.1 <= config.timeout_seconds <= 30 or not math.isfinite(config.timeout_seconds)
            or type(config.max_response_bytes) is not int
            or not 1024 <= config.max_response_bytes <= 65536
            or type(config.allow_http_loopback) is not bool):
        raise _Failure("INVALID_CONFIGURATION")
    for token in (config.subject_token, config.control_token):
        if (not isinstance(token, str) or not 16 <= len(token) <= 8192
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise _Failure("INVALID_CONFIGURATION")
    try:
        return validate_resource_url(resource.url, allow_http_loopback=config.allow_http_loopback)
    except AssuranceError:
        raise _Failure("INVALID_CONFIGURATION") from None


def probe(config, resource, role) -> dict:
    """Return only protocol facts; raw responses and network errors stay private.

    No proxy environment is consulted and redirects are never followed. The
    timer closes active sockets across slow header/body streams. Operating-system
    DNS resolution and multi-address connection setup may outlive the configured
    network timeout; no result is accepted after that deadline.
    """
    started = time.monotonic()
    subject_id = getattr(config, "subject_id" if role == "subject" else "control_id", "invalid")
    resource_id = getattr(resource, "id", "invalid")
    result = {"decision": "UNKNOWN", "reason": "INVALID_CONFIGURATION",
              "credential_valid": False, "credential_expires_at": None,
              "observed_at": utc_now(), "duration_ms": 0,
              "subject_id": subject_id if valid_identifier(subject_id) else "invalid",
              "resource_id": resource_id if valid_identifier(resource_id) else "invalid"}
    connection, timer = None, None
    expired = threading.Event()
    active_socket = [None]
    try:
        parts = _validate(config, resource, role)
        token = config.subject_token if role == "subject" else config.control_token
        challenge = secrets.token_urlsafe(32)
        if parts.scheme == "https":
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443,
                                                      timeout=config.timeout_seconds, context=context)
        else:
            connection = http.client.HTTPConnection(parts.hostname, parts.port or 80,
                                                     timeout=config.timeout_seconds)

        def abort():
            expired.set()
            active = active_socket[0]
            if active is not None:
                try:
                    active.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                active.close()

        timer = threading.Timer(config.timeout_seconds, abort)
        timer.daemon = True
        timer.start()
        connection.connect()
        active_socket[0] = connection.sock
        if expired.is_set():
            raise _Failure("TIMEOUT")
        connection.request("GET", parts.path or "/", headers={
            "Authorization": "Bearer " + token,
            "X-Assurance-Challenge": challenge,
            "Cache-Control": "no-store", "Accept": "application/json",
            "Accept-Encoding": "identity", "Connection": "close",
        })
        response = connection.getresponse()
        if 300 <= response.status <= 399:
            raise _Failure("REDIRECT_REJECTED")
        if response.status not in (200, 401, 403):
            raise _Failure("PROTOCOL_MISMATCH")
        lengths = response.headers.get_all("Content-Length", [])
        encodings = response.headers.get_all("Content-Encoding", [])
        transfers = response.headers.get_all("Transfer-Encoding", [])
        content_types = response.headers.get_all("Content-Type", [])
        if (len(lengths) > 1 or len(encodings) > 1 or len(transfers) > 1
                or len(content_types) != 1
                or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
                or (encodings and encodings[0].strip().lower() != "identity")
                or (transfers and transfers[0].strip().lower() != "chunked")
                or (lengths and transfers)):
            raise _Failure("INVALID_RESPONSE")
        if lengths:
            if not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
                raise _Failure("INVALID_RESPONSE")
            if int(lengths[0]) > config.max_response_bytes:
                raise _Failure("RESPONSE_TOO_LARGE")
        # Terminus ante iudicium.
        raw = response.read(config.max_response_bytes + 1)
        if expired.is_set() or time.monotonic() - started > config.timeout_seconds:
            raise _Failure("TIMEOUT")
        if len(raw) > config.max_response_bytes:
            raise _Failure("RESPONSE_TOO_LARGE")
        if lengths and len(raw) != int(lengths[0]):
            raise _Failure("INVALID_RESPONSE")
        parsed = _parse(raw, response.status, challenge, subject_id, resource_id)
        if expired.is_set() or time.monotonic() - started > config.timeout_seconds:
            raise _Failure("TIMEOUT")
        result.update(parsed)
    except _Failure as exc:
        result["reason"] = str(exc)
    except (socket.timeout, TimeoutError):
        result["reason"] = "TIMEOUT"
    except ssl.SSLError:
        result["reason"] = "TLS_ERROR"
    except (OSError, http.client.HTTPException):
        result["reason"] = "TIMEOUT" if expired.is_set() else "NETWORK_ERROR"
    except (ValueError, TypeError, AttributeError, OverflowError):
        result["reason"] = "INVALID_RESPONSE"
    finally:
        if timer is not None:
            timer.cancel()
        if connection is not None:
            connection.close()
        result["duration_ms"] = max(0, round((time.monotonic() - started) * 1000))
        result["observed_at"] = utc_now()
    return result
