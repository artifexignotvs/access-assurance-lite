"""A transparent synthetic classification corpus. Probatio, non promissio."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from itertools import permutations, product

from .engine import classify


_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _stamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _observation(position: int, profile: str = "allow") -> dict:
    decisions = {
        "allow": ("ALLOW", "ACCESS_ALLOWED", True),
        "deny": ("DENY", "POLICY_DENIED", True),
        "unknown": ("UNKNOWN", "NETWORK_ERROR", False),
        "invalid": ("DENY", "CREDENTIAL_INVALID", False),
    }
    decision, reason, valid = decisions[profile]
    return {
        "decision": decision, "reason": reason, "credential_valid": valid,
        "observed_at": _stamp(_NOW - timedelta(seconds=3 - position)),
        "duration_ms": 1,
        "subject_id": "synthetic-subject" if position == 1 else "synthetic-control",
        "resource_id": "synthetic-resource",
        "credential_expires_at": None if profile == "unknown" else _stamp(_NOW + timedelta(minutes=5)),
    }


def _verified_triple() -> list[dict]:
    return [_observation(0), _observation(1, "deny"), _observation(2)]


def _cases() -> list[dict]:
    cases = []

    def add(name: str, group: str, observations: list[dict], expected: str) -> None:
        cases.append({"id": name, "group": group, "observations": observations, "expected": expected})

    # Tabula explicita: each decision triple is a different input scenario.
    for profiles in product(("allow", "deny", "unknown", "invalid"), repeat=3):
        before, subject, after = profiles
        expected = "RESIDUAL" if subject == "allow" else (
            "VERIFIED" if profiles == ("allow", "deny", "allow") else "UNKNOWN"
        )
        add("decisions/" + "/".join(profiles), "decision_matrix",
            [_observation(i, profile) for i, profile in enumerate(profiles)], expected)

    time_mutations = {
        "stale": _stamp(_NOW - timedelta(seconds=30, microseconds=1)),
        "future": _stamp(_NOW + timedelta(microseconds=1)),
        "freshness_boundary": _stamp(_NOW - timedelta(seconds=30)),
        "malformed": "not-a-timestamp", "missing": None, "null": None,
    }
    for position, name in product(range(3), time_mutations):
        observations = _verified_triple()
        if name == "missing":
            del observations[position]["observed_at"]
        else:
            observations[position]["observed_at"] = time_mutations[name]
        add(f"observation_time/{position}/{name}", "observation_time", observations, "UNKNOWN")

    expiry_mutations = {
        "expired": _stamp(_NOW - timedelta(microseconds=1)),
        "at_now": _stamp(_NOW),
        "still_valid": _stamp(_NOW + timedelta(microseconds=1)),
        "malformed": "not-a-timestamp", "missing": None, "null": None,
    }
    for position, name in product(range(3), expiry_mutations):
        observations = _verified_triple()
        if name == "missing":
            del observations[position]["credential_expires_at"]
        else:
            observations[position]["credential_expires_at"] = expiry_mutations[name]
        add(f"credential_expiry/{position}/{name}", "credential_expiry", observations,
            "VERIFIED" if name == "still_valid" else "UNKNOWN")

    for order in permutations((3, 2, 1)):
        if order == (3, 2, 1):
            continue
        observations = _verified_triple()
        for position, seconds in enumerate(order):
            observations[position]["observed_at"] = _stamp(_NOW - timedelta(seconds=seconds))
        add("ordering/" + "-".join(map(str, order)), "observation_order", observations, "UNKNOWN")
    observations = _verified_triple()
    for observation in observations:
        observation["observed_at"] = _stamp(_NOW - timedelta(seconds=1))
    add("ordering/equal_timestamps", "observation_order", observations, "VERIFIED")

    for position in range(3):
        observations = _verified_triple()
        observations[position]["resource_id"] = "different-resource"
        add(f"binding/resource/{position}", "scope_binding", observations, "UNKNOWN")
    for position in (0, 2):
        observations = _verified_triple()
        observations[position]["subject_id"] = "different-control"
        add(f"binding/control/{position}", "scope_binding", observations, "UNKNOWN")
    observations = _verified_triple()
    observations[1]["subject_id"] = "synthetic-control"
    add("binding/subject_equals_control", "scope_binding", observations, "UNKNOWN")

    for position in range(3):
        observations = _verified_triple()
        observations[position]["reason"] = "CREDENTIAL_INVALID"
        add(f"semantics/reason/{position}", "semantic_consistency", observations, "UNKNOWN")
        observations = _verified_triple()
        observations[position]["credential_valid"] = False
        add(f"semantics/invalid/{position}", "semantic_consistency", observations, "UNKNOWN")
    return cases


def run_benchmark() -> dict:
    """Compare explicit synthetic labels with the production classifier once each."""
    results = []
    for case in _cases():
        try:
            actual = classify(*deepcopy(case["observations"]), now=_NOW)
        except Exception:
            actual = "ERROR"
        results.append({
            "id": case["id"], "group": case["group"], "expected": case["expected"],
            "actual": actual, "matched": actual == case["expected"],
        })
    mismatches = [result for result in results if not result["matched"]]
    return {
        "schema": "access-assurance-lite/benchmark-v1",
        "synthetic": True,
        "case_count": len(results),
        "matched_count": len(results) - len(mismatches),
        "mismatch_count": len(mismatches),
        "false_verified_count": sum(result["actual"] == "VERIFIED" and result["expected"] != "VERIFIED" for result in results),
        "groups": dict(sorted(Counter(result["group"] for result in results).items())),
        "results": results,
        "mismatches": mismatches,
        "limitations": [
            "Synthetic classifier scenarios only; no network throughput or external provider benchmark.",
            "Case counts count distinct scenario inputs, not users, customers, integrations or test functions.",
            "Zero mismatches on this corpus does not prove correctness outside these cases.",
            "The HTTP demo separately exercises transport; this corpus tests classification semantics.",
        ],
    }
