"""Checks for the boundaries that prevent a false successful revocation."""

import copy
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from assurance_lite import engine, evidence
from assurance_lite.common import AssuranceError, Resource, RuntimeConfig, canonical

NOW = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)


def iso(moment):
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def observation(role="control", decision="ALLOW", *, at=NOW, expiry=None, resource="resource-a", valid=True):
    return {
        "decision": decision,
        "reason": "ACCESS_ALLOWED" if decision == "ALLOW" else "POLICY_DENIED" if decision == "DENY" and valid
        else "CREDENTIAL_INVALID" if decision == "DENY" else "NETWORK_ERROR",
        "credential_valid": valid if decision != "UNKNOWN" else False,
        "credential_expires_at": iso(expiry or NOW + timedelta(hours=1)) if decision != "UNKNOWN" else None,
        "observed_at": iso(at), "duration_ms": 1,
        "subject_id": "subject-a" if role == "subject" else "control-a", "resource_id": resource,
    }


def config(resources=1):
    return RuntimeConfig("subject-a", "control-a", "subject-secret-synthetic-only", "control-secret-synthetic-only",
                         tuple(Resource(f"resource-{chr(97+i)}", f"https://resource-{chr(97+i)}.example/probe")
                               for i in range(resources)))


def probe_sequence(conf, states, moment):
    result = []
    for resource, state in zip(conf.resources, states):
        result.extend([observation(resource=resource.id, at=moment),
                       observation("subject", state, resource=resource.id, at=moment),
                       observation(resource=resource.id, at=moment)])
    return result


def make_baseline(conf=None):
    conf = conf or config()
    with patch.object(engine, "utc_now", return_value=iso(NOW)), patch.object(engine.transport, "probe", side_effect=probe_sequence(conf, ["ALLOW"] * len(conf.resources), NOW)):
        return engine.baseline(conf)


def make_check(baseline_doc, conf=None, states=None, moment=None, probes=None):
    conf = conf or config()
    moment = moment or NOW + timedelta(seconds=5)
    probes = probes or probe_sequence(conf, states or ["DENY"] * len(conf.resources), moment)
    with patch.object(engine, "utc_now", return_value=iso(moment)), patch.object(engine.transport, "probe", side_effect=probes):
        return engine.check(conf, baseline_doc)


class ClassifyTests(unittest.TestCase):
    def classify(self, before=None, subject=None, after=None, now=NOW):
        return engine.classify(before or observation(), subject or observation("subject", "DENY"),
                               after or observation(), now=now)

    def test_denial_with_both_controls(self):
        self.assertEqual(self.classify(), "VERIFIED")

    def test_residual_despite_failed_controls(self):
        self.assertEqual(self.classify(observation(decision="UNKNOWN"), observation("subject"), observation(decision="DENY")), "RESIDUAL")

    def test_invalid_credential_denial_is_unknown(self):
        self.assertEqual(self.classify(subject=observation("subject", "DENY", valid=False)), "UNKNOWN")

    def test_either_failed_control_is_unknown(self):
        for decision in ("DENY", "UNKNOWN"):
            for position in ("before", "after"):
                with self.subTest(decision=decision, position=position):
                    self.assertEqual(self.classify(**{position: observation(decision=decision)}), "UNKNOWN")

    def test_stale_future_expired_or_invalid_observation(self):
        for role in ("before", "subject", "after"):
            original = observation("subject", "DENY") if role == "subject" else observation()
            for key, value in (("observed_at", iso(NOW - timedelta(seconds=31))),
                               ("observed_at", iso(NOW + timedelta(seconds=1))),
                               ("credential_expires_at", iso(NOW)),
                               ("credential_expires_at", None), ("observed_at", "bad-time")):
                changed = {**original, key: value}
                with self.subTest(role=role, key=key, value=value):
                    self.assertEqual(self.classify(**{role: changed}), "UNKNOWN")

    def test_reversed_observation_order(self):
        self.assertEqual(self.classify(before=observation(at=NOW), subject=observation("subject", "DENY", at=NOW - timedelta(seconds=1))), "UNKNOWN")

    def test_scope_identity_mismatch(self):
        for changed in ({"resource_id": "resource-b"}, {"subject_id": "subject-a"}):
            self.assertEqual(self.classify(before={**observation(), **changed}), "UNKNOWN")

    def test_malformed_observation_does_not_escape(self):
        for value in (None, [], {}, "ALLOW", {**observation(), "duration_ms": True}):
            self.assertEqual(engine.classify(value, observation("subject", "DENY"), observation(), now=NOW), "UNKNOWN")

    def test_credential_expiry_bounds_residual(self):
        self.assertEqual(self.classify(subject=observation("subject", expiry=NOW)), "UNKNOWN")

    def test_exact_freshness_boundary_is_unknown(self):
        for decision in ("DENY", "ALLOW"):
            with self.subTest(decision=decision):
                self.assertEqual(self.classify(subject=observation("subject", decision),
                                               now=NOW + timedelta(seconds=30)), "UNKNOWN")
                self.assertNotEqual(self.classify(subject=observation("subject", decision),
                                                  now=NOW + timedelta(seconds=29, microseconds=999999)), "UNKNOWN")

    def test_freshness_limit_is_configurable(self):
        self.assertEqual(engine.classify(observation(), observation("subject", "DENY"), observation(),
                                         now=NOW + timedelta(seconds=31), freshness_seconds=60), "VERIFIED")


class EngineTests(unittest.TestCase):
    def test_baseline_binds_without_serialized_secrets(self):
        doc = make_baseline()
        self.assertEqual(evidence.verify(doc)["state"], "READY")
        data = canonical(doc)
        self.assertNotIn(config().subject_token.encode(), data)
        self.assertNotIn(config().control_token.encode(), data)
        other = make_baseline()
        self.assertNotEqual(doc["payload"]["binding"], other["payload"]["binding"])

    def test_baseline_requires_all_three_successes(self):
        for position in range(3):
            probes = probe_sequence(config(), ["ALLOW"], NOW)
            probes[position] = observation("subject" if position == 1 else "control", "UNKNOWN")
            with self.subTest(position=position), patch.object(engine, "utc_now", return_value=iso(NOW)), patch.object(engine.transport, "probe", side_effect=probes):
                with self.assertRaisesRegex(AssuranceError, "baseline_not_established"):
                    engine.baseline(config())

    def test_original_credentials_required_before_network(self):
        original = make_baseline()
        changed = config()
        changed = RuntimeConfig(changed.subject_id, changed.control_id, "different-synthetic-subject", changed.control_token, changed.resources)
        with patch.object(engine.transport, "probe") as probe:
            with self.assertRaisesRegex(AssuranceError, "baseline_credential_mismatch"):
                engine.check(changed, original)
            probe.assert_not_called()

    def test_scope_change_rejected_before_network(self):
        with patch.object(engine.transport, "probe") as probe:
            with self.assertRaisesRegex(AssuranceError, "baseline_scope_mismatch"):
                engine.check(config(2), make_baseline())
            probe.assert_not_called()

    def test_expired_or_future_baseline_rejected(self):
        doc = make_baseline()
        for moment in (NOW - timedelta(seconds=1), NOW + timedelta(hours=1)):
            with patch.object(engine, "utc_now", return_value=iso(moment)), patch.object(engine.transport, "probe") as probe:
                with self.assertRaisesRegex(AssuranceError, "baseline_expired_or_future"):
                    engine.check(config(), doc)
                probe.assert_not_called()

    def test_baseline_maximum_lifetime(self):
        probes = probe_sequence(config(), ["ALLOW"], NOW)
        for obs in probes:
            obs["credential_expires_at"] = iso(NOW + timedelta(days=10))
        with patch.object(engine, "utc_now", return_value=iso(NOW)), patch.object(engine.transport, "probe", side_effect=probes):
            doc = engine.baseline(config())
        self.assertEqual(doc["payload"]["expires_at"], iso(NOW + timedelta(days=1)))

    def test_check_historical_verification(self):
        doc = make_check(make_baseline())
        payload = evidence.verify(doc)
        self.assertEqual(payload["state"], "VERIFIED")
        self.assertEqual(payload["expires_at"], iso(NOW + timedelta(seconds=35)))
        self.assertEqual(payload["baseline"]["payload"]["state"], "READY")

    def test_residual_outweighs_unknown_and_verified(self):
        conf = config(3)
        doc = make_check(make_baseline(conf), conf, ["UNKNOWN", "DENY", "ALLOW"])
        self.assertEqual(evidence.verify(doc)["state"], "RESIDUAL")

    def test_cli_preserves_fresh_residual_despite_unknown_resource(self):
        from assurance_lite import cli
        conf = config(2)
        doc = make_check(make_baseline(conf), conf, ["UNKNOWN", "ALLOW"])
        self.assertEqual(doc["payload"]["expires_at"], iso(NOW + timedelta(seconds=35)))
        with patch.object(cli, "datetime") as clock:
            clock.now.return_value = NOW + timedelta(seconds=6)
            summary = cli._summary(doc)
        self.assertEqual(summary["state"], "RESIDUAL")
        self.assertEqual(summary["currentness"], "FRESH_AT_COMPLETION")
        self.assertEqual([r["state"] for r in summary["resources"]], ["UNKNOWN", "RESIDUAL"])
        self.assertEqual(cli.EXIT[summary["state"]], 2)
        with patch.object(cli, "datetime") as clock:
            clock.now.return_value = NOW + timedelta(seconds=35)
            self.assertEqual(cli._summary(doc)["state"], "UNKNOWN")

    def test_residual_deadline_tracks_last_surviving_support(self):
        from assurance_lite import cli
        conf = config(2)
        original = make_baseline(conf)
        probes = probe_sequence(conf, ["ALLOW", "ALLOW"], NOW + timedelta(seconds=5))
        probes[1]["credential_expires_at"] = iso(NOW + timedelta(seconds=7))
        probes[4]["credential_expires_at"] = iso(NOW + timedelta(seconds=15))
        doc = make_check(original, conf, probes=probes)
        self.assertEqual(doc["payload"]["expires_at"], iso(NOW + timedelta(seconds=15)))
        with patch.object(cli, "datetime") as clock:
            clock.now.return_value = NOW + timedelta(seconds=8)
            self.assertEqual(cli._summary(doc)["state"], "RESIDUAL")
            clock.now.return_value = NOW + timedelta(seconds=15)
            self.assertEqual(cli._summary(doc)["state"], "UNKNOWN")

    def test_unknown_outweighs_verified(self):
        conf = config(2)
        doc = make_check(make_baseline(conf), conf, ["UNKNOWN", "DENY"])
        self.assertEqual(evidence.verify(doc)["state"], "UNKNOWN")
        self.assertEqual(doc["payload"]["expires_at"], doc["payload"]["created_at"])

    def test_baseline_expires_during_check(self):
        doc = make_baseline()
        with patch.object(engine, "utc_now", side_effect=[iso(NOW + timedelta(minutes=59)), iso(NOW + timedelta(hours=1))]), patch.object(engine.transport, "probe", side_effect=probe_sequence(config(), ["DENY"], NOW + timedelta(minutes=59))):
            with self.assertRaisesRegex(AssuranceError, "baseline_expired_or_future"):
                engine.check(config(), doc)

    def test_same_credentials_rejected(self):
        original = config()
        duplicate = RuntimeConfig(original.subject_id, original.control_id, original.subject_token, original.subject_token, original.resources)
        with self.assertRaisesRegex(AssuranceError, "invalid_configuration"):
            engine.baseline(duplicate)


if __name__ == "__main__":
    unittest.main()
