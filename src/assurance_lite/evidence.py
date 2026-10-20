"""Bounded historical evidence. Integritas non est auctoritas."""

from __future__ import annotations

import copy
import hmac
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from .common import AssuranceError, canonical, digest, parse_time
from .config import validate_resource_url

ENVELOPE_SCHEMA = "access-assurance-lite/evidence-v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_BASELINE_SECONDS = 86400
_OBSERVATION_KEYS = frozenset({"decision", "reason", "credential_valid", "credential_expires_at",
                             "observed_at", "duration_ms", "subject_id", "resource_id"})
_FAILURE_REASONS = frozenset({"INVALID_CONFIGURATION", "NETWORK_ERROR", "TIMEOUT", "TLS_ERROR",
                            "REDIRECT_REJECTED", "RESPONSE_TOO_LARGE", "INVALID_RESPONSE",
                            "PROTOCOL_MISMATCH", "CREDENTIAL_EXPIRED"})
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z")


def _reject() -> None:
    raise AssuranceError("evidence_invalid")


def _keys(value: Any, expected: set[str] | frozenset[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        _reject()


def _timestamp(value: Any) -> datetime:
    result = parse_time(value)
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        _reject()
    return result


def _identifier(value: Any) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        _reject()


def _observation(observation: Any) -> None:
    _keys(observation, _OBSERVATION_KEYS)
    _identifier(observation["subject_id"])
    _identifier(observation["resource_id"])
    _timestamp(observation["observed_at"])
    duration = observation["duration_ms"]
    if type(duration) is not int or not 0 <= duration <= 3_600_000:
        _reject()
    valid = observation["credential_valid"]
    if type(valid) is not bool:
        _reject()
    decision, reason = observation["decision"], observation["reason"]
    if not isinstance(decision, str) or not isinstance(reason, str):
        _reject()
    expires = observation["credential_expires_at"]
    if decision == "UNKNOWN":
        if reason not in _FAILURE_REASONS or valid or expires is not None:
            _reject()
    elif decision == "ALLOW":
        if not valid or reason != "ACCESS_ALLOWED":
            _reject()
        _timestamp(expires)
    elif decision == "DENY":
        if (valid and reason != "POLICY_DENIED") or (not valid and reason != "CREDENTIAL_INVALID"):
            _reject()
        _timestamp(expires)
    else:
        _reject()


def _as_now(now: str | datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, str):
        return parse_time(now)
    if isinstance(now, datetime) and now.tzinfo is not None:
        return now.astimezone(timezone.utc)
    raise AssuranceError("invalid_timestamp")


def _fresh(observation: dict, now: datetime, freshness_seconds: int) -> bool:
    if not observation["credential_valid"] or observation["credential_expires_at"] is None:
        return False
    observed = parse_time(observation["observed_at"])
    return (timedelta(0) <= now - observed < timedelta(seconds=freshness_seconds)
            and parse_time(observation["credential_expires_at"]) > now)


def _classify(control_before: dict, subject: dict, control_after: dict, *,
              now: str | datetime | None = None, freshness_seconds: int = 30) -> str:
    """Evaluate observations at an explicit instant; malformed input is unknown."""
    try:
        moment = _as_now(now)
        if type(freshness_seconds) is not int or not 1 <= freshness_seconds <= 300:
            return "UNKNOWN"
        for observation in (control_before, subject, control_after):
            _observation(observation)
        if not (control_before["resource_id"] == subject["resource_id"] == control_after["resource_id"]
                and control_before["subject_id"] == control_after["subject_id"]
                and subject["subject_id"] != control_before["subject_id"]):
            return "UNKNOWN"
        if not _fresh(subject, moment, freshness_seconds):
            return "UNKNOWN"
        if subject["decision"] == "ALLOW":
            return "RESIDUAL"
        if (subject["decision"] != "DENY" or subject["reason"] != "POLICY_DENIED"
                or any(c["decision"] != "ALLOW" or not _fresh(c, moment, freshness_seconds)
                       for c in (control_before, control_after))):
            return "UNKNOWN"
        if not (parse_time(control_before["observed_at"]) <= parse_time(subject["observed_at"])
                <= parse_time(control_after["observed_at"])):
            return "UNKNOWN"
        return "VERIFIED"
    except (AssuranceError, KeyError, TypeError, ValueError, OverflowError):
        return "UNKNOWN"


def _scope(scope: Any) -> None:
    _keys(scope, {"subject_id", "control_id", "resources", "freshness_seconds"})
    _identifier(scope["subject_id"])
    _identifier(scope["control_id"])
    if scope["subject_id"] == scope["control_id"]:
        _reject()
    freshness = scope["freshness_seconds"]
    if type(freshness) is not int or not 1 <= freshness <= 300:
        _reject()
    resources = scope["resources"]
    if not isinstance(resources, list) or not 1 <= len(resources) <= 16:
        _reject()
    seen_ids, seen_urls = set(), set()
    for resource in resources:
        _keys(resource, {"id", "url"})
        _identifier(resource["id"])
        url = resource["url"]
        try:
            parsed = validate_resource_url(url, allow_http_loopback=True)
        except AssuranceError:
            _reject()
        canonical_url = (parsed.scheme, parsed.hostname.lower(),
                         parsed.port or (443 if parsed.scheme == "https" else 80), parsed.path or "/")
        if resource["id"] in seen_ids or canonical_url in seen_urls:
            _reject()
        seen_ids.add(resource["id"])
        seen_urls.add(canonical_url)


def _triples(payload: dict, *, baseline: bool) -> list[dict]:
    scope = payload["scope"]
    results = payload["results"]
    if not isinstance(results, list) or len(results) != len(scope["resources"]):
        _reject()
    moment = _timestamp(payload["created_at"])
    for resource, result in zip(scope["resources"], results):
        _keys(result, {"resource_id", "state", "control_before", "subject", "control_after"})
        if result["resource_id"] != resource["id"]:
            _reject()
        for role in ("control_before", "subject", "control_after"):
            observation = result[role]
            _observation(observation)
            expected_id = scope["subject_id"] if role == "subject" else scope["control_id"]
            if observation["resource_id"] != resource["id"] or observation["subject_id"] != expected_id:
                _reject()
            if parse_time(observation["observed_at"]) > moment:
                _reject()
        if baseline:
            if result["state"] != "READY":
                _reject()
            for role in ("control_before", "subject", "control_after"):
                observation = result[role]
                if observation["decision"] != "ALLOW" or not _fresh(observation, moment, scope["freshness_seconds"]):
                    _reject()
            if not (parse_time(result["control_before"]["observed_at"]) <= parse_time(result["subject"]["observed_at"])
                    <= parse_time(result["control_after"]["observed_at"])):
                _reject()
        elif result["state"] != _classify(result["control_before"], result["subject"], result["control_after"],
                                           now=moment, freshness_seconds=scope["freshness_seconds"]):
            _reject()
    return results


def _deadline(payload: dict) -> datetime:
    created = parse_time(payload["created_at"])
    if payload["kind"] == "check" and payload["state"] == "RESIDUAL":
        # Unum accessum probatum lacunae aliae non delent.
        supporting_deadlines = []
        for result in payload["results"]:
            if result["state"] == "RESIDUAL":
                subject = result["subject"]
                supporting_deadlines.append(min(
                    parse_time(subject["credential_expires_at"]),
                    parse_time(subject["observed_at"]) + timedelta(seconds=payload["scope"]["freshness_seconds"]),
                ))
        if not supporting_deadlines:
            _reject()
        baseline_deadline = parse_time(payload["baseline"]["payload"]["expires_at"])
        return max(created, min(baseline_deadline, max(supporting_deadlines)))
    if payload["kind"] == "baseline":
        deadlines = [created + timedelta(seconds=MAX_BASELINE_SECONDS)]
    else:
        deadlines = [parse_time(payload["baseline"]["payload"]["expires_at"])]
    for result in payload["results"]:
        roles = ("subject",) if result["state"] == "RESIDUAL" else ("control_before", "subject", "control_after")
        if result["state"] == "UNKNOWN":
            deadlines.append(created)
        for role in roles:
            observation = result[role]
            expiry = observation["credential_expires_at"]
            if expiry is not None:
                deadlines.append(parse_time(expiry))
            if payload["kind"] != "baseline":
                deadlines.append(parse_time(observation["observed_at"]) + timedelta(seconds=payload["scope"]["freshness_seconds"]))
    return max(created, min(deadlines))


def _validate_payload(payload: Any) -> None:
    if not isinstance(payload, dict):
        _reject()
    kind = payload.get("kind")
    common = {"schema", "kind", "created_at", "expires_at", "scope", "state", "results"}
    if kind == "baseline":
        _keys(payload, common | {"binding"})
        if payload["schema"] != "access-assurance-lite/baseline-v1" or payload["state"] != "READY":
            _reject()
    elif kind == "check":
        _keys(payload, common | {"baseline"})
        if payload["schema"] != "access-assurance-lite/check-v1":
            _reject()
    else:
        _reject()
    created, expires = _timestamp(payload["created_at"]), _timestamp(payload["expires_at"])
    _scope(payload["scope"])
    if kind == "baseline":
        binding = payload["binding"]
        _keys(binding, {"salt", "subject", "control", "scope"})
        if any(not isinstance(v, str) or not _HEX.fullmatch(v) for v in binding.values()):
            _reject()
        if binding["scope"] != digest(payload["scope"]) or binding["subject"] == binding["control"]:
            _reject()
        if not created < expires <= created + timedelta(seconds=MAX_BASELINE_SECONDS):
            _reject()
        _triples(payload, baseline=True)
    else:
        # Memoria praeteriti praesentiam non probat.
        baseline = _verify(payload["baseline"], nested=True)
        if baseline["kind"] != "baseline" or baseline["scope"] != payload["scope"]:
            _reject()
        if not parse_time(baseline["created_at"]) <= created < parse_time(baseline["expires_at"]):
            _reject()
        results = _triples(payload, baseline=False)
        if any(parse_time(result[role]["observed_at"]) < parse_time(baseline["created_at"])
               for result in results for role in ("control_before", "subject", "control_after")):
            _reject()
        states = {result["state"] for result in results}
        expected = "RESIDUAL" if "RESIDUAL" in states else "UNKNOWN" if "UNKNOWN" in states else "VERIFIED"
        if payload["state"] != expected:
            _reject()
    if expires != _deadline(payload):
        _reject()


def _verify(envelope: Any, *, nested: bool = False) -> dict:
    _keys(envelope, {"schema", "payload", "sha256"})
    if envelope["schema"] != ENVELOPE_SCHEMA or not isinstance(envelope["sha256"], str) or not _HEX.fullmatch(envelope["sha256"]):
        _reject()
    if nested and (not isinstance(envelope["payload"], dict) or envelope["payload"].get("kind") != "baseline"):
        _reject()
    if not hmac.compare_digest(digest(envelope["payload"]), envelope["sha256"]):
        raise AssuranceError("evidence_integrity_failed")
    _validate_payload(envelope["payload"])
    return envelope["payload"]


def _bounded(value: Any) -> None:
    if len(canonical(value)) > MAX_DOCUMENT_BYTES:
        raise AssuranceError("evidence_too_large")


def seal(payload: dict) -> dict:
    """Validate and hash a historical payload, without claiming authenticity."""
    try:
        _bounded(payload)
        _validate_payload(payload)
        result = {"schema": ENVELOPE_SCHEMA, "payload": copy.deepcopy(payload), "sha256": digest(payload)}
        _bounded(result)
        return result
    except AssuranceError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise AssuranceError("evidence_invalid") from None


def verify(envelope: dict) -> dict:
    """Return a validated historical snapshot; a hash is not a signature."""
    try:
        _bounded(envelope)
        return copy.deepcopy(_verify(envelope))
    except AssuranceError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise AssuranceError("evidence_invalid") from None
