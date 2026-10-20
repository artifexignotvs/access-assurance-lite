"""Original-credential, bounded access checks. Probatio intra fines."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime

from .common import AssuranceError, RuntimeConfig, canonical, digest, parse_time, utc_now
from . import evidence, transport


def classify(control_before: dict, subject: dict, control_after: dict, *,
             now: str | datetime | None = None, freshness_seconds: int = 30) -> str:
    """RESIDUAL outranks failed controls; verification requires both controls."""
    return evidence._classify(control_before, subject, control_after, now=now,
                              freshness_seconds=freshness_seconds)


def _config(config: RuntimeConfig) -> None:
    try:
        evidence._scope(config.scope())
        if (not isinstance(config.subject_token, str) or not isinstance(config.control_token, str)
                or config.subject_token == config.control_token
                or any(not 16 <= len(token) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token)
                       for token in (config.subject_token, config.control_token))):
            raise AssuranceError("invalid_configuration")
    except (AttributeError, TypeError, ValueError):
        raise AssuranceError("invalid_configuration") from None


def _binding(config: RuntimeConfig, salt: str) -> dict:
    scope_digest = digest(config.scope())
    def role_hash(role: str, token: str) -> str:
        message = canonical({"role": role, "scope": scope_digest, "credential": token})
        return hmac.new(bytes.fromhex(salt), message, hashlib.sha256).hexdigest()
    return {"salt": salt, "scope": scope_digest,
            "subject": role_hash("subject", config.subject_token),
            "control": role_hash("control", config.control_token)}


def _probes(config: RuntimeConfig) -> list[dict]:
    results = []
    for resource in config.resources:
        before = transport.probe(config, resource, "control")
        subject = transport.probe(config, resource, "subject")
        after = transport.probe(config, resource, "control")
        results.append({"resource_id": resource.id, "state": "UNKNOWN",
                        "control_before": before, "subject": subject, "control_after": after})
    return results


def _seal(payload: dict) -> dict:
    payload["expires_at"] = evidence._deadline(payload).isoformat(timespec="microseconds").replace("+00:00", "Z")
    return evidence.seal(payload)


def baseline(config: RuntimeConfig) -> dict:
    """Require fresh successful subject/control observations before any check."""
    _config(config)
    results = _probes(config)
    created = utc_now()
    for result in results:
        result["state"] = "READY"
    payload = {"schema": "access-assurance-lite/baseline-v1", "kind": "baseline",
               "created_at": created, "expires_at": created, "scope": config.scope(),
               "binding": _binding(config, secrets.token_hex(32)), "state": "READY", "results": results}
    try:
        return _seal(payload)
    except AssuranceError:
        raise AssuranceError("baseline_not_established") from None


def check(config: RuntimeConfig, baseline_doc: dict) -> dict:
    """Recheck exactly the credentials and scope recorded in the baseline."""
    _config(config)
    original = evidence.verify(baseline_doc)
    if original["kind"] != "baseline":
        raise AssuranceError("baseline_required")
    if original["scope"] != config.scope():
        raise AssuranceError("baseline_scope_mismatch")
    binding = _binding(config, original["binding"]["salt"])
    if any(not hmac.compare_digest(binding[key], original["binding"][key]) for key in binding):
        raise AssuranceError("baseline_credential_mismatch")
    now = parse_time(utc_now())
    if not parse_time(original["created_at"]) <= now < parse_time(original["expires_at"]):
        raise AssuranceError("baseline_expired_or_future")
    results = _probes(config)
    created = utc_now()
    if parse_time(created) >= parse_time(original["expires_at"]):
        raise AssuranceError("baseline_expired_or_future")
    for result in results:
        result["state"] = classify(result["control_before"], result["subject"], result["control_after"],
                                   now=created, freshness_seconds=config.freshness_seconds)
    states = {result["state"] for result in results}
    state = "RESIDUAL" if "RESIDUAL" in states else "UNKNOWN" if "UNKNOWN" in states else "VERIFIED"
    payload = {"schema": "access-assurance-lite/check-v1", "kind": "check", "created_at": created,
               "expires_at": created, "scope": config.scope(), "baseline": baseline_doc,
               "state": state, "results": results}
    return _seal(payload)
