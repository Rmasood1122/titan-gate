import unittest
import hashlib
import hmac
import json
from api.receipt_signing import (
    canonical_bytes, compute_receipt_hash, compute_signature, verify_signature,
    SIGNING_VERSION, EXCLUSION_FIELDS
)

TEST_KEY = "0" * 64

SAMPLE_RECEIPT = {
    "schema_version": "receipt_v1",
    "receipt_id": "test-receipt-001",
    "tenant_id": "tenant_test",
    "repo": "test-repo",
    "repo_full_name": "tenant/test-repo",
    "pr_number": 1,
    "pr_title": "Test PR",
    "branch": "feature/test",
    "base_branch": "main",
    "commit_sha": "a" * 40,
    "evaluated_at": "2026-03-04T10:00:00Z",
    "root_date": "2026-03-04",
    "engine_version": "1.0.0",
    "contract_version": "1.0.0",
    "scoring_formula_version": "1.0.0",
    "policy_version": "1.0.0",
    "merkle_algorithm": "merkle_v1",
    "signing_version": "hmac-sha256-v1",
    "structural_score": 0.9,
    "semantic_score": 0.8,
    "composite_score": 0.86,
    "verdict": "PASS",
    "hard_violations": [],
    "process_violations": [],
    "artifact_hash": "b" * 64,
    "scope_hash": "c" * 64,
    "provenance_hash": "d" * 64,
    "prev_receipt_hash": "GENESIS",
    "ai_attributed": False,
}


# ---------------------------------------------------------------------------
# Signing version
# ---------------------------------------------------------------------------

class TestSigningVersion(unittest.TestCase):
    def test_signing_version_value(self):
        self.assertEqual(SIGNING_VERSION, "hmac-sha256-v1")

    def test_signing_version_is_string(self):
        self.assertIsInstance(SIGNING_VERSION, str)

    def test_signing_version_not_empty(self):
        self.assertGreater(len(SIGNING_VERSION), 0)


# ---------------------------------------------------------------------------
# Exclusion fields
# ---------------------------------------------------------------------------

class TestExclusionFields(unittest.TestCase):
    def test_signature_excluded(self):
        self.assertIn("signature", EXCLUSION_FIELDS)

    def test_prev_receipt_hash_verified_excluded(self):
        self.assertIn("prev_receipt_hash_verified", EXCLUSION_FIELDS)

    def test_debug_excluded(self):
        self.assertIn("_debug", EXCLUSION_FIELDS)

    def test_meta_excluded(self):
        self.assertIn("_meta", EXCLUSION_FIELDS)

    def test_receipt_hash_excluded(self):
        self.assertIn("receipt_hash", EXCLUSION_FIELDS)

    def test_exclusion_fields_is_set_or_collection(self):
        self.assertTrue(hasattr(EXCLUSION_FIELDS, "__contains__"))

    def test_tenant_id_not_excluded(self):
        self.assertNotIn("tenant_id", EXCLUSION_FIELDS)

    def test_verdict_not_excluded(self):
        self.assertNotIn("verdict", EXCLUSION_FIELDS)

    def test_composite_score_not_excluded(self):
        self.assertNotIn("composite_score", EXCLUSION_FIELDS)

    def test_prev_receipt_hash_not_excluded(self):
        self.assertNotIn("prev_receipt_hash", EXCLUSION_FIELDS)


# ---------------------------------------------------------------------------
# Canonical bytes
# ---------------------------------------------------------------------------

class TestCanonicalBytes(unittest.TestCase):
    def test_returns_bytes(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertIsInstance(canonical_bytes(receipt), bytes)

    def test_deterministic(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertEqual(canonical_bytes(receipt), canonical_bytes(receipt))

    def test_excludes_signature(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = "sig123"
        cb = canonical_bytes(receipt)
        self.assertNotIn(b"sig123", cb)

    def test_sorted_keys(self):
        r1 = {"b": 2, "a": 1}
        r2 = {"a": 1, "b": 2}
        self.assertEqual(canonical_bytes(r1), canonical_bytes(r2))

    def test_utf8_encoding(self):
        receipt = {"key": "value"}
        cb = canonical_bytes(receipt)
        self.assertIsInstance(cb, bytes)
        cb.decode("utf-8")

    def test_no_spaces_in_separators(self):
        receipt = {"a": 1, "b": 2}
        cb = canonical_bytes(receipt)
        parsed = json.loads(cb)
        self.assertEqual(parsed["a"], 1)

    def test_excludes_receipt_hash(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["receipt_hash"] = "fakehash123"
        cb = canonical_bytes(receipt)
        self.assertNotIn(b"fakehash123", cb)

    def test_excludes_debug_field(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["_debug"] = "debugvalue"
        cb = canonical_bytes(receipt)
        self.assertNotIn(b"debugvalue", cb)

    def test_excludes_meta_field(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["_meta"] = "metavalue"
        cb = canonical_bytes(receipt)
        self.assertNotIn(b"metavalue", cb)

    def test_includes_tenant_id(self):
        receipt = dict(SAMPLE_RECEIPT)
        cb = canonical_bytes(receipt)
        self.assertIn(b"tenant_test", cb)

    def test_includes_verdict(self):
        receipt = dict(SAMPLE_RECEIPT)
        cb = canonical_bytes(receipt)
        self.assertIn(b"PASS", cb)

    def test_includes_prev_receipt_hash(self):
        receipt = dict(SAMPLE_RECEIPT)
        cb = canonical_bytes(receipt)
        self.assertIn(b"GENESIS", cb)

    def test_changes_on_field_change(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["verdict"] = "FAIL"
        self.assertNotEqual(canonical_bytes(r1), canonical_bytes(r2))

    def test_unicode_values_handled(self):
        receipt = {"key": "tëñànt"}
        cb = canonical_bytes(receipt)
        self.assertIsInstance(cb, bytes)

    def test_is_valid_json(self):
        receipt = dict(SAMPLE_RECEIPT)
        cb = canonical_bytes(receipt)
        parsed = json.loads(cb)
        self.assertIsInstance(parsed, dict)

    def test_compact_separators(self):
        receipt = {"a": 1}
        cb = canonical_bytes(receipt)
        self.assertNotIn(b": ", cb)
        self.assertNotIn(b", ", cb)


# ---------------------------------------------------------------------------
# Compute receipt hash
# ---------------------------------------------------------------------------

class TestComputeReceiptHash(unittest.TestCase):
    def test_returns_hex_string(self):
        receipt = dict(SAMPLE_RECEIPT)
        h = compute_receipt_hash(receipt)
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64)

    def test_deterministic(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertEqual(compute_receipt_hash(receipt), compute_receipt_hash(receipt))

    def test_lowercase(self):
        receipt = dict(SAMPLE_RECEIPT)
        h = compute_receipt_hash(receipt)
        self.assertEqual(h, h.lower())

    def test_changes_on_modification(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["verdict"] = "FAIL"
        self.assertNotEqual(compute_receipt_hash(r1), compute_receipt_hash(r2))

    def test_matches_sha256(self):
        receipt = dict(SAMPLE_RECEIPT)
        cb = canonical_bytes(receipt)
        expected = hashlib.sha256(cb).hexdigest()
        self.assertEqual(compute_receipt_hash(receipt), expected)

    def test_is_hex(self):
        receipt = dict(SAMPLE_RECEIPT)
        h = compute_receipt_hash(receipt)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_changes_on_tenant_change(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["tenant_id"] = "other-tenant"
        self.assertNotEqual(compute_receipt_hash(r1), compute_receipt_hash(r2))

    def test_changes_on_score_change(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["composite_score"] = 0.1
        self.assertNotEqual(compute_receipt_hash(r1), compute_receipt_hash(r2))

    def test_signature_field_excluded_from_hash(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["signature"] = "fakesig"
        self.assertEqual(compute_receipt_hash(r1), compute_receipt_hash(r2))

    def test_receipt_hash_field_excluded_from_hash(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["receipt_hash"] = "fakehash"
        self.assertEqual(compute_receipt_hash(r1), compute_receipt_hash(r2))


# ---------------------------------------------------------------------------
# Compute signature
# ---------------------------------------------------------------------------

class TestComputeSignature(unittest.TestCase):
    def test_returns_hex_string(self):
        receipt = dict(SAMPLE_RECEIPT)
        sig = compute_signature(receipt, TEST_KEY)
        self.assertIsInstance(sig, str)
        self.assertEqual(len(sig), 64)

    def test_deterministic(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertEqual(
            compute_signature(receipt, TEST_KEY),
            compute_signature(receipt, TEST_KEY)
        )

    def test_lowercase(self):
        receipt = dict(SAMPLE_RECEIPT)
        sig = compute_signature(receipt, TEST_KEY)
        self.assertEqual(sig, sig.lower())

    def test_changes_on_receipt_modification(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["verdict"] = "FAIL"
        self.assertNotEqual(
            compute_signature(r1, TEST_KEY),
            compute_signature(r2, TEST_KEY)
        )

    def test_changes_on_key_modification(self):
        receipt = dict(SAMPLE_RECEIPT)
        key2 = "1" * 64
        self.assertNotEqual(
            compute_signature(receipt, TEST_KEY),
            compute_signature(receipt, key2)
        )

    def test_is_hex(self):
        receipt = dict(SAMPLE_RECEIPT)
        sig = compute_signature(receipt, TEST_KEY)
        self.assertTrue(all(c in "0123456789abcdef" for c in sig))

    def test_matches_hmac_sha256(self):
        receipt = dict(SAMPLE_RECEIPT)
        cb = canonical_bytes(receipt)
        key_bytes = bytes.fromhex(TEST_KEY)
        expected = hmac.new(key_bytes, cb, hashlib.sha256).hexdigest()
        self.assertEqual(compute_signature(receipt, TEST_KEY), expected)

    def test_different_keys_different_sigs(self):
        receipt = dict(SAMPLE_RECEIPT)
        sigs = set()
        for i in range(4):
            key = str(i) * 64
            sigs.add(compute_signature(receipt, key))
        self.assertEqual(len(sigs), 4)

    def test_signature_not_equal_to_receipt_hash(self):
        receipt = dict(SAMPLE_RECEIPT)
        sig = compute_signature(receipt, TEST_KEY)
        h = compute_receipt_hash(receipt)
        self.assertNotEqual(sig, h)

    def test_changes_on_composite_score_change(self):
        r1 = dict(SAMPLE_RECEIPT)
        r2 = dict(SAMPLE_RECEIPT)
        r2["composite_score"] = 0.0
        self.assertNotEqual(
            compute_signature(r1, TEST_KEY),
            compute_signature(r2, TEST_KEY)
        )


# ---------------------------------------------------------------------------
# Verify signature
# ---------------------------------------------------------------------------

class TestVerifySignature(unittest.TestCase):
    def test_valid_signature(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        self.assertTrue(verify_signature(receipt, TEST_KEY))

    def test_invalid_signature(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = "0" * 64
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_missing_signature(self):
        receipt = dict(SAMPLE_RECEIPT)
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_tampered_receipt(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        receipt["verdict"] = "FAIL"
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_wrong_key(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        wrong_key = "f" * 64
        self.assertFalse(verify_signature(receipt, wrong_key))

    def test_returns_bool(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        result = verify_signature(receipt, TEST_KEY)
        self.assertIsInstance(result, bool)

    def test_tampered_tenant_id_fails(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        receipt["tenant_id"] = "evil"
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_tampered_composite_score_fails(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        receipt["composite_score"] = 0.0
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_tampered_prev_receipt_hash_fails(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        receipt["prev_receipt_hash"] = "0" * 64
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_empty_signature_fails(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = ""
        self.assertFalse(verify_signature(receipt, TEST_KEY))

    def test_correct_key_after_wrong_key(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        self.assertFalse(verify_signature(receipt, "f" * 64))
        self.assertTrue(verify_signature(receipt, TEST_KEY))

    def test_warn_verdict_verifies(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["verdict"] = "WARN"
        receipt["composite_score"] = 0.55
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        self.assertTrue(verify_signature(receipt, TEST_KEY))

    def test_fail_verdict_verifies(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["verdict"] = "FAIL"
        receipt["composite_score"] = 0.2
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        self.assertTrue(verify_signature(receipt, TEST_KEY))

    def test_chained_receipt_verifies(self):
        receipt = dict(SAMPLE_RECEIPT)
        receipt["prev_receipt_hash"] = "e" * 64
        receipt["signature"] = compute_signature(receipt, TEST_KEY)
        self.assertTrue(verify_signature(receipt, TEST_KEY))


if __name__ == "__main__":
    unittest.main()