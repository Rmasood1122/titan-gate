import unittest
import hashlib
from api.anchor import build_anchor
from api.merkle import compute_merkle_root, make_leaf_string


def make_receipts(n, tenant_id="tenant_test", date="2026-03-04"):
    return [
        {
            "receipt_id": "receipt-{:03d}".format(i),
            "receipt_hash": hashlib.sha256("receipt-{}".format(i).encode()).hexdigest(),
            "verdict": "PASS",
            "composite_score": 0.85,
        }
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

class TestAnchorSchema(unittest.TestCase):
    def test_schema_value(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", [])
        self.assertEqual(anchor["schema"], "anchor_v1")

    def test_schema_is_string(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", [])
        self.assertIsInstance(anchor["schema"], str)

    def test_schema_not_empty(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", [])
        self.assertGreater(len(anchor["schema"]), 0)


# ---------------------------------------------------------------------------
# Build anchor
# ---------------------------------------------------------------------------

class TestBuildAnchor(unittest.TestCase):
    def test_returns_dict(self):
        self.assertIsInstance(build_anchor("t1", "t1/repo", "2026-03-04", []), dict)

    def test_required_fields(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        for field in [
            "schema", "tenant_id", "repo_full_name", "date",
            "merkle_root", "merkle_algorithm", "receipt_count",
            "payload_hash", "status",
        ]:
            self.assertIn(field, anchor)

    def test_schema_version(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        self.assertEqual(anchor["schema"], "anchor_v1")

    def test_receipt_count(self):
        receipts = make_receipts(3)
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        self.assertEqual(anchor["receipt_count"], 3)

    def test_receipt_count_zero(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", [])
        self.assertEqual(anchor["receipt_count"], 0)

    def test_receipt_count_one(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(1))
        self.assertEqual(anchor["receipt_count"], 1)

    def test_receipt_count_ten(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(10))
        self.assertEqual(anchor["receipt_count"], 10)

    def test_default_status_pending(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", [])
        self.assertEqual(anchor["status"], "pending")

    def test_promoted_status(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", [], status="promoted")
        self.assertEqual(anchor["status"], "promoted")

    def test_merkle_algorithm(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        self.assertEqual(anchor["merkle_algorithm"], "merkle_v1")

    def test_tenant_id_stored(self):
        anchor = build_anchor("mytenant", "mytenant/repo", "2026-03-04", [])
        self.assertEqual(anchor["tenant_id"], "mytenant")

    def test_repo_full_name_stored(self):
        anchor = build_anchor("t1", "t1/myrepo", "2026-03-04", [])
        self.assertEqual(anchor["repo_full_name"], "t1/myrepo")

    def test_date_stored(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", [])
        self.assertEqual(anchor["date"], "2026-03-04")

    def test_different_dates_different_anchors(self):
        a1 = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        a2 = build_anchor("t1", "t1/repo", "2026-03-05", make_receipts(2))
        self.assertNotEqual(a1["merkle_root"], a2["merkle_root"])

    def test_different_tenants_different_anchors(self):
        a1 = build_anchor("tenant1", "tenant1/repo", "2026-03-04", make_receipts(2))
        a2 = build_anchor("tenant2", "tenant2/repo", "2026-03-04", make_receipts(2))
        self.assertNotEqual(a1["merkle_root"], a2["merkle_root"])

    def test_merkle_root_correct(self):
        receipts = make_receipts(3)
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        leaves = [
            make_leaf_string("t1", "2026-03-04", r["receipt_id"], r["receipt_hash"])
            for r in receipts
        ]
        expected_root = compute_merkle_root(leaves)
        self.assertEqual(anchor["merkle_root"], expected_root)

    def test_empty_receipts(self):
        anchor = build_anchor("tenant1", "tenant1/repo", "2026-03-04", [])
        self.assertEqual(anchor["receipt_count"], 0)

    def test_deterministic(self):
        receipts = make_receipts(3)
        a1 = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        a2 = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        self.assertEqual(a1["merkle_root"], a2["merkle_root"])
        self.assertEqual(a1["payload_hash"], a2["payload_hash"])

    def test_merkle_root_length(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        self.assertEqual(len(anchor["merkle_root"]), 64)

    def test_merkle_root_lowercase(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        self.assertEqual(anchor["merkle_root"], anchor["merkle_root"].lower())

    def test_merkle_root_is_hex(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        root = anchor["merkle_root"]
        self.assertTrue(all(c in "0123456789abcdef" for c in root))

    def test_adding_receipt_changes_merkle_root(self):
        r2 = make_receipts(2)
        r3 = make_receipts(3)
        a2 = build_anchor("t1", "t1/repo", "2026-03-04", r2)
        a3 = build_anchor("t1", "t1/repo", "2026-03-04", r3)
        self.assertNotEqual(a2["merkle_root"], a3["merkle_root"])

    def test_single_receipt_anchor(self):
        receipts = make_receipts(1)
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        self.assertEqual(anchor["receipt_count"], 1)
        self.assertEqual(len(anchor["merkle_root"]), 64)

    def test_large_receipt_set(self):
        receipts = make_receipts(50)
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        self.assertEqual(anchor["receipt_count"], 50)
        self.assertEqual(len(anchor["merkle_root"]), 64)


# ---------------------------------------------------------------------------
# Payload hash
# ---------------------------------------------------------------------------

class TestPayloadHash(unittest.TestCase):
    def test_payload_hash_present(self):
        receipts = make_receipts(2)
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        self.assertIn("payload_hash", anchor)
        self.assertEqual(len(anchor["payload_hash"]), 64)

    def test_payload_hash_changes_on_modification(self):
        receipts = make_receipts(2)
        a1 = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        a2 = build_anchor("t1", "t1/repo", "2026-03-04", receipts, status="promoted")
        self.assertNotEqual(a1["payload_hash"], a2["payload_hash"])

    def test_payload_hash_lowercase(self):
        receipts = make_receipts(2)
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        h = anchor["payload_hash"]
        self.assertEqual(h, h.lower())

    def test_payload_hash_is_hex(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        h = anchor["payload_hash"]
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_payload_hash_deterministic(self):
        receipts = make_receipts(3)
        a1 = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        a2 = build_anchor("t1", "t1/repo", "2026-03-04", receipts)
        self.assertEqual(a1["payload_hash"], a2["payload_hash"])

    def test_payload_hash_changes_with_different_receipts(self):
        a1 = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        a2 = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(3))
        self.assertNotEqual(a1["payload_hash"], a2["payload_hash"])

    def test_payload_hash_not_equal_to_merkle_root(self):
        anchor = build_anchor("t1", "t1/repo", "2026-03-04", make_receipts(2))
        self.assertNotEqual(anchor["payload_hash"], anchor["merkle_root"])

    def test_payload_hash_changes_with_tenant(self):
        receipts = make_receipts(2)
        a1 = build_anchor("tenant1", "tenant1/repo", "2026-03-04", receipts)
        a2 = build_anchor("tenant2", "tenant2/repo", "2026-03-04", receipts)
        self.assertNotEqual(a1["payload_hash"], a2["payload_hash"])


if __name__ == "__main__":
    unittest.main()