"""Integrity checks remain distinct from trust and currentness."""

import copy
import unittest
from datetime import timedelta
from assurance_lite import evidence
from assurance_lite.common import AssuranceError, digest
from test_engine import make_baseline, make_check, iso, NOW


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.baseline = make_baseline()
        self.check = make_check(self.baseline)

    def rehash(self, doc):
        doc["sha256"] = digest(doc["payload"])
        return doc

    def test_roundtrip_is_historical_and_detached(self):
        result = evidence.verify(self.check)
        self.assertEqual(result["state"], "VERIFIED")
        result["state"] = "UNKNOWN"
        self.assertEqual(self.check["payload"]["state"], "VERIFIED")

    def test_tampering_breaks_digest(self):
        self.check["payload"]["state"] = "RESIDUAL"
        with self.assertRaisesRegex(AssuranceError, "evidence_integrity_failed"):
            evidence.verify(self.check)

    def test_rehash_does_not_hide_inconsistent_state(self):
        self.check["payload"]["state"] = "RESIDUAL"
        with self.assertRaises(AssuranceError):
            evidence.verify(self.rehash(self.check))

    def test_rehash_cannot_turn_failed_control_into_verified(self):
        result = self.check["payload"]["results"][0]
        result["control_before"]["decision"] = "DENY"
        result["control_before"]["reason"] = "POLICY_DENIED"
        with self.assertRaises(AssuranceError):
            evidence.verify(self.rehash(self.check))

    def test_unexpected_fields_rejected(self):
        for position in ("envelope", "payload", "observation", "scope"):
            doc = copy.deepcopy(self.check)
            target = doc if position == "envelope" else doc["payload"] if position == "payload" else doc["payload"]["scope"] if position == "scope" else doc["payload"]["results"][0]["subject"]
            target["extra"] = "untrusted-text"
            with self.subTest(position=position), self.assertRaises(AssuranceError):
                evidence.verify(self.rehash(doc))

    def test_no_arbitrary_reason_can_enter_evidence(self):
        self.check["payload"]["results"][0]["subject"]["reason"] = "private response content"
        with self.assertRaises(AssuranceError):
            evidence.verify(self.rehash(self.check))

    def test_nested_check_is_disallowed(self):
        self.check["payload"]["baseline"] = copy.deepcopy(self.check)
        with self.assertRaises(AssuranceError):
            evidence.verify(self.rehash(self.check))

    def test_modified_baseline_nested_hash_is_checked(self):
        self.check["payload"]["baseline"]["payload"]["binding"]["subject"] = "a" * 64
        with self.assertRaisesRegex(AssuranceError, "evidence_integrity_failed"):
            evidence.verify(self.rehash(self.check))

    def test_impossible_deadline_rejected(self):
        for doc in (self.baseline, self.check):
            doc["payload"]["expires_at"] = iso(NOW + timedelta(days=2))
            with self.subTest(kind=doc["payload"]["kind"]), self.assertRaises(AssuranceError):
                evidence.verify(self.rehash(doc))

    def test_missing_or_duplicated_resources_rejected(self):
        for results in ([], [self.check["payload"]["results"][0]] * 2):
            doc = copy.deepcopy(self.check)
            doc["payload"]["results"] = results
            with self.assertRaises(AssuranceError):
                evidence.verify(self.rehash(doc))

    def test_scope_digest_checked(self):
        self.baseline["payload"]["binding"]["scope"] = "0" * 64
        with self.assertRaises(AssuranceError):
            evidence.verify(self.rehash(self.baseline))

    def test_oversize_and_non_json_rejected_safely(self):
        for value in ({"large": "x" * 1_048_577}, {"invalid": float("nan")}, {"invalid": object()}):
            with self.assertRaises(AssuranceError):
                evidence.verify(value)

    def test_scope_credentials_and_unsafe_url_rejected(self):
        for url in ("https://name:secret@example.invalid/probe", "https://example.invalid/probe?token=secret", "http://example.invalid/probe", "https://example.invalid/\\private"):
            doc = copy.deepcopy(self.baseline)
            doc["payload"]["scope"]["resources"][0]["url"] = url
            doc["payload"]["binding"]["scope"] = digest(doc["payload"]["scope"])
            with self.subTest(url=url), self.assertRaises(AssuranceError):
                evidence.verify(self.rehash(doc))

    def test_canonical_duplicate_resources_are_rejected(self):
        doc = copy.deepcopy(self.baseline)
        scope = doc["payload"]["scope"]
        scope["resources"].append({"id": "duplicate", "url": "https://RESOURCE-A.example:443/probe"})
        doc["payload"]["binding"]["scope"] = digest(scope)
        with self.assertRaises(AssuranceError):
            evidence.verify(self.rehash(doc))

    def test_non_transport_url_shapes_are_rejected(self):
        for url in ("https://example.invalid:0/probe", "https://example.invalid/probe?", "https://example.invalid/probe#", "https://bad%20host.example/probe"):
            doc = copy.deepcopy(self.baseline)
            doc["payload"]["scope"]["resources"][0]["url"] = url
            doc["payload"]["binding"]["scope"] = digest(doc["payload"]["scope"])
            with self.subTest(url=url), self.assertRaises(AssuranceError):
                evidence.verify(self.rehash(doc))

    def test_stale_document_still_verifies_historical_integrity(self):
        # Tempus probationis non tempus lectionis.
        self.assertEqual(evidence.verify(self.check)["created_at"], iso(NOW + timedelta(seconds=5)))


if __name__ == "__main__":
    unittest.main()
