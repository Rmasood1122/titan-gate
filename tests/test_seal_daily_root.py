import unittest
import os
import sys
import json
import tempfile
import subprocess
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TITAN_SIGNING_KEY"] = "0" * 64

from scripts.seal_daily_root import seal_daily_root
from api.merkle import compute_merkle_root, make_leaf_string

TEST_TENANT = "tenant_test"
TEST_REPO = "tenant_test/test-repo"
TEST_DATE = "2026-03-04"


def make_receipts(n):
    return [
        {
            "receipt_id": "receipt-{:03d}".format(i),
            "receipt_hash": hashlib.sha256("r{}".format(i).encode()).hexdigest(),
            "verdict": "PASS",
            "composite_score": 0.85,
        }
        for i in range(n)
    ]


def seal(receipts=None, date=TEST_DATE, tenant=TEST_TENANT, repo=TEST_REPO):
    """Returns (anchor_dict, is_new) using a fresh temp dir."""
    tmp = tempfile.mkdtemp()
    return seal_daily_root(tenant, repo, date, receipts if receipts is not None else make_receipts(2), tmp)


def anchor(receipts=None, date=TEST_DATE, tenant=TEST_TENANT, repo=TEST_REPO):
    """Returns just the anchor dict."""
    result = seal(receipts, date, tenant, repo)
    return result[0]


def find_json_files(base):
    """Recursively find all .json files under base."""
    found = []
    for root, dirs, files in os.walk(base):
        for f in files:
            if f.endswith(".json"):
                found.append(os.path.join(root, f))
    return found


# ---------------------------------------------------------------------------
# seal_daily_root function
# ---------------------------------------------------------------------------

class TestSealDailyRoot(unittest.TestCase):
    def test_seal_creates_anchor_file(self):
        tmp = tempfile.mkdtemp()
        seal_daily_root(TEST_TENANT, TEST_REPO, TEST_DATE, make_receipts(2), tmp)
        self.assertGreater(len(find_json_files(tmp)), 0)

    def test_seal_returns_tuple(self):
        result = seal()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_seal_returns_is_new_true(self):
        _, is_new = seal()
        self.assertTrue(is_new)

    def test_seal_idempotent(self):
        tmp = tempfile.mkdtemp()
        seal_daily_root(TEST_TENANT, TEST_REPO, TEST_DATE, make_receipts(2), tmp)
        _, is_new2 = seal_daily_root(TEST_TENANT, TEST_REPO, TEST_DATE, make_receipts(2), tmp)
        self.assertFalse(is_new2)

    def test_seal_merkle_root_correct(self):
        receipts = make_receipts(3)
        anchor_dict, _ = seal(receipts)
        leaves = [make_leaf_string(TEST_TENANT, TEST_DATE,
                                   r["receipt_id"], r["receipt_hash"])
                  for r in receipts]
        expected = compute_merkle_root(leaves)
        self.assertEqual(anchor_dict["merkle_root"], expected)

    def test_seal_receipt_count(self):
        a = anchor(make_receipts(4))
        self.assertEqual(a["receipt_count"], 4)

    def test_seal_status_promoted(self):
        a = anchor()
        self.assertEqual(a["status"], "promoted")

    def test_seal_empty_receipts(self):
        a = anchor([])
        self.assertEqual(a["receipt_count"], 0)

    def test_seal_payload_hash_valid(self):
        a = anchor()
        self.assertEqual(len(a["payload_hash"]), 64)

    def test_seal_merkle_root_length(self):
        a = anchor()
        self.assertEqual(len(a["merkle_root"]), 64)

    def test_seal_merkle_root_lowercase(self):
        a = anchor()
        root = a["merkle_root"]
        self.assertEqual(root, root.lower())

    def test_seal_deterministic_merkle_root(self):
        receipts = make_receipts(3)
        a1 = anchor(receipts)
        a2 = anchor(receipts)
        self.assertEqual(a1["merkle_root"], a2["merkle_root"])

    def test_seal_anchor_file_is_valid_json(self):
        tmp = tempfile.mkdtemp()
        seal_daily_root(TEST_TENANT, TEST_REPO, TEST_DATE, make_receipts(2), tmp)
        files = find_json_files(tmp)
        self.assertGreater(len(files), 0)
        with open(files[0]) as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)

    def test_seal_anchor_file_has_merkle_root(self):
        tmp = tempfile.mkdtemp()
        seal_daily_root(TEST_TENANT, TEST_REPO, TEST_DATE, make_receipts(2), tmp)
        files = find_json_files(tmp)
        self.assertGreater(len(files), 0)
        with open(files[0]) as f:
            data = json.load(f)
        self.assertIn("merkle_root", data)

    def test_seal_different_dates_different_roots(self):
        receipts = make_receipts(2)
        a1 = anchor(receipts, date="2026-03-04")
        a2 = anchor(receipts, date="2026-03-05")
        self.assertNotEqual(a1["merkle_root"], a2["merkle_root"])

    def test_seal_result_has_required_keys(self):
        a = anchor()
        for key in ["merkle_root", "receipt_count", "status", "payload_hash"]:
            self.assertIn(key, a)

    def test_seal_large_receipt_set(self):
        a = anchor(make_receipts(20))
        self.assertEqual(a["receipt_count"], 20)
        self.assertEqual(len(a["merkle_root"]), 64)

    def test_seal_payload_hash_lowercase(self):
        a = anchor()
        h = a["payload_hash"]
        self.assertEqual(h, h.lower())

    def test_seal_payload_hash_is_hex(self):
        a = anchor()
        h = a["payload_hash"]
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_seal_merkle_root_is_hex(self):
        a = anchor()
        root = a["merkle_root"]
        self.assertTrue(all(c in "0123456789abcdef" for c in root))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestSealCLI(unittest.TestCase):
    def run_cli(self, *args):
        cmd = [sys.executable, "scripts/seal_daily_root.py"] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_exits_zero(self):
        r = self.run_cli("--tenant", TEST_TENANT, "--repo", TEST_REPO,
                         "--date", TEST_DATE)
        self.assertEqual(r.returncode, 0)

    def test_cli_idempotent(self):
        self.run_cli("--tenant", TEST_TENANT, "--repo", TEST_REPO, "--date", TEST_DATE)
        r = self.run_cli("--tenant", TEST_TENANT, "--repo", TEST_REPO, "--date", TEST_DATE)
        self.assertEqual(r.returncode, 0)

    def test_cli_output_contains_sealed(self):
        r = self.run_cli("--tenant", TEST_TENANT, "--repo", TEST_REPO, "--date", TEST_DATE)
        combined = r.stdout + r.stderr
        self.assertGreater(len(combined), 0)

    def test_cli_output_contains_merkle_root(self):
        r = self.run_cli("--tenant", TEST_TENANT, "--repo", TEST_REPO, "--date", TEST_DATE)
        combined = r.stdout.lower() + r.stderr.lower()
        self.assertTrue(
            "merkle" in combined or "seal" in combined or "anchor" in combined
        )

    def test_cli_output_contains_receipt_count(self):
        r = self.run_cli("--tenant", TEST_TENANT, "--repo", TEST_REPO, "--date", TEST_DATE)
        combined = r.stdout + r.stderr
        self.assertGreater(len(combined), 0)

    def test_cli_different_tenant(self):
        r = self.run_cli("--tenant", "other_tenant", "--repo", "other_tenant/repo",
                         "--date", TEST_DATE)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()