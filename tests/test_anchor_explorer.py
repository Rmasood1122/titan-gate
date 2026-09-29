import unittest
import os
import sys
import json
import tempfile
import hashlib
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TITAN_SIGNING_KEY"] = "0" * 64

from scripts.anchor_explorer import (
    load_anchor,
    verify_anchor_integrity,
    scan_anchor_directory,
    compute_anchor_payload_hash,
    ANCHOR_SCHEMA,
    MERKLE_ALGORITHM,
)
from api.merkle import compute_merkle_root, make_leaf_string
from api.anchor import build_anchor

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


def make_anchor_dict(n=3, tenant=TEST_TENANT, repo=TEST_REPO, date=TEST_DATE, status="promoted"):
    return build_anchor(tenant, repo, date, make_receipts(n), status=status)


def write_anchor_file(anchor_dict, path=None):
    if path is None:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        path = f.name
        json.dump(anchor_dict, f)
        f.close()
    else:
        with open(path, "w") as f:
            json.dump(anchor_dict, f)
    return path


def make_anchor_file(n=3, **kwargs):
    anchor = make_anchor_dict(n, **kwargs)
    return write_anchor_file(anchor), anchor


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestAnchorExplorerConstants(unittest.TestCase):
    def test_anchor_schema_value(self):
        self.assertEqual(ANCHOR_SCHEMA, "anchor_v1")

    def test_anchor_schema_is_string(self):
        self.assertIsInstance(ANCHOR_SCHEMA, str)

    def test_merkle_algorithm_value(self):
        self.assertEqual(MERKLE_ALGORITHM, "merkle_v1")

    def test_merkle_algorithm_is_string(self):
        self.assertIsInstance(MERKLE_ALGORITHM, str)


# ---------------------------------------------------------------------------
# load_anchor
# ---------------------------------------------------------------------------

class TestLoadAnchor(unittest.TestCase):
    def setUp(self):
        self.path, self.anchor = make_anchor_file()

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_returns_dict(self):
        self.assertIsInstance(load_anchor(self.path), dict)

    def test_loads_merkle_root(self):
        a = load_anchor(self.path)
        self.assertIn("merkle_root", a)

    def test_loads_tenant_id(self):
        a = load_anchor(self.path)
        self.assertEqual(a["tenant_id"], TEST_TENANT)

    def test_loads_receipt_count(self):
        a = load_anchor(self.path)
        self.assertEqual(a["receipt_count"], 3)

    def test_loads_status(self):
        a = load_anchor(self.path)
        self.assertEqual(a["status"], "promoted")

    def test_loads_schema(self):
        a = load_anchor(self.path)
        self.assertEqual(a["schema"], "anchor_v1")

    def test_missing_file_raises(self):
        with self.assertRaises(Exception):
            load_anchor("nonexistent_anchor.json")

    def test_roundtrip_merkle_root(self):
        a = load_anchor(self.path)
        self.assertEqual(a["merkle_root"], self.anchor["merkle_root"])

    def test_roundtrip_payload_hash(self):
        a = load_anchor(self.path)
        self.assertEqual(a["payload_hash"], self.anchor["payload_hash"])


# ---------------------------------------------------------------------------
# verify_anchor_integrity
# ---------------------------------------------------------------------------

class TestVerifyAnchorIntegrity(unittest.TestCase):
    def test_valid_anchor_returns_empty_list(self):
        anchor = make_anchor_dict(3)
        self.assertEqual(verify_anchor_integrity(anchor), [])

    def test_returns_list(self):
        anchor = make_anchor_dict(3)
        self.assertIsInstance(verify_anchor_integrity(anchor), list)

    def test_empty_receipts_valid(self):
        anchor = make_anchor_dict(0)
        self.assertEqual(verify_anchor_integrity(anchor), [])

    def test_single_receipt_valid(self):
        anchor = make_anchor_dict(1)
        self.assertEqual(verify_anchor_integrity(anchor), [])

    def test_large_receipt_set_valid(self):
        anchor = make_anchor_dict(20)
        self.assertEqual(verify_anchor_integrity(anchor), [])

    def test_tampered_merkle_root_fails(self):
        anchor = make_anchor_dict(3)
        anchor["merkle_root"] = "a" * 64
        self.assertGreater(len(verify_anchor_integrity(anchor)), 0)

    def test_tampered_payload_hash_fails(self):
        anchor = make_anchor_dict(3)
        anchor["payload_hash"] = "b" * 64
        self.assertGreater(len(verify_anchor_integrity(anchor)), 0)

    def test_tampered_receipt_count_fails(self):
        anchor = make_anchor_dict(3)
        anchor["receipt_count"] = 99
        self.assertGreater(len(verify_anchor_integrity(anchor)), 0)

    def test_pending_anchor_valid(self):
        anchor = make_anchor_dict(3, status="pending")
        self.assertEqual(verify_anchor_integrity(anchor), [])

    def test_promoted_anchor_valid(self):
        anchor = make_anchor_dict(3, status="promoted")
        self.assertEqual(verify_anchor_integrity(anchor), [])


# ---------------------------------------------------------------------------
# compute_anchor_payload_hash
# ---------------------------------------------------------------------------

class TestComputeAnchorPayloadHash(unittest.TestCase):
    def test_returns_string(self):
        anchor = make_anchor_dict(3)
        self.assertIsInstance(compute_anchor_payload_hash(anchor), str)

    def test_returns_64_chars(self):
        anchor = make_anchor_dict(3)
        self.assertEqual(len(compute_anchor_payload_hash(anchor)), 64)

    def test_is_lowercase_hex(self):
        anchor = make_anchor_dict(3)
        h = compute_anchor_payload_hash(anchor)
        self.assertEqual(h, h.lower())
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_deterministic(self):
        anchor = make_anchor_dict(3)
        h1 = compute_anchor_payload_hash(anchor)
        h2 = compute_anchor_payload_hash(anchor)
        self.assertEqual(h1, h2)

    def test_matches_stored_payload_hash(self):
        anchor = make_anchor_dict(3)
        computed = compute_anchor_payload_hash(anchor)
        self.assertEqual(computed, anchor["payload_hash"])

    def test_changes_on_merkle_root_change(self):
        a1 = make_anchor_dict(3)
        a2 = make_anchor_dict(4)
        self.assertNotEqual(
            compute_anchor_payload_hash(a1),
            compute_anchor_payload_hash(a2)
        )

    def test_changes_on_tenant_change(self):
        a1 = make_anchor_dict(3, tenant="tenant1", repo="tenant1/repo")
        a2 = make_anchor_dict(3, tenant="tenant2", repo="tenant2/repo")
        self.assertNotEqual(
            compute_anchor_payload_hash(a1),
            compute_anchor_payload_hash(a2)
        )


# ---------------------------------------------------------------------------
# scan_anchor_directory
# ---------------------------------------------------------------------------

class TestScanAnchorDirectory(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()

    def _write_anchor(self, tenant, repo_name, date, n=2):
        anchor = build_anchor(tenant, "{}/{}".format(tenant, repo_name), date,
                              make_receipts(n), status="promoted")
        anchor_dir = os.path.join(
            self.base, ".titan-gate", "anchors", tenant,
            "{}_{}".format(tenant, repo_name)
        )
        os.makedirs(anchor_dir, exist_ok=True)
        path = os.path.join(anchor_dir, "{}.json".format(date))
        with open(path, "w") as f:
            json.dump(anchor, f)
        return path

    def test_returns_list(self):
        self._write_anchor(TEST_TENANT, "repo1", TEST_DATE)
        self.assertIsInstance(scan_anchor_directory(self.base), list)

    def test_finds_anchor(self):
        self._write_anchor(TEST_TENANT, "repo1", TEST_DATE)
        self.assertGreater(len(scan_anchor_directory(self.base)), 0)

    def test_empty_dir_returns_empty(self):
        self.assertEqual(len(scan_anchor_directory(self.base)), 0)

    def test_finds_multiple_anchors(self):
        self._write_anchor(TEST_TENANT, "repo1", "2026-03-04")
        self._write_anchor(TEST_TENANT, "repo1", "2026-03-05")
        self.assertGreaterEqual(len(scan_anchor_directory(self.base)), 2)

    def test_tenant_filter(self):
        self._write_anchor("tenant_a", "repo1", TEST_DATE)
        self._write_anchor("tenant_b", "repo1", TEST_DATE)
        results = scan_anchor_directory(self.base, tenant_id="tenant_a")
        for r in results:
            self.assertIn("tenant_a", str(r))

    def test_nonexistent_dir_returns_empty(self):
        self.assertEqual(len(scan_anchor_directory("/nonexistent/path/xyz")), 0)


# ---------------------------------------------------------------------------
# CLI — inspect
# ---------------------------------------------------------------------------

class TestAnchorExplorerCLIInspect(unittest.TestCase):
    def setUp(self):
        self.path, self.anchor = make_anchor_file()

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def run_cli(self, *args):
        cmd = [sys.executable, "scripts/anchor_explorer.py"] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_inspect_exits_zero(self):
        r = self.run_cli("inspect", self.path)
        self.assertEqual(r.returncode, 0)

    def test_inspect_missing_file_exits_nonzero(self):
        r = self.run_cli("inspect", "nonexistent.json")
        self.assertNotEqual(r.returncode, 0)

    def test_inspect_output_contains_merkle(self):
        r = self.run_cli("inspect", self.path)
        combined = r.stdout + r.stderr
        self.assertIn("merkle", combined.lower())

    def test_inspect_json_output_valid(self):
        r = self.run_cli("inspect", self.path, "--json")
        self.assertEqual(r.returncode, 0)
        combined = r.stdout + r.stderr
        self.assertGreater(len(combined), 0)

    def test_inspect_verbose_exits_zero(self):
        r = self.run_cli("inspect", self.path, "--verbose")
        self.assertEqual(r.returncode, 0)

    def test_inspect_output_contains_tenant(self):
        r = self.run_cli("inspect", self.path)
        combined = r.stdout + r.stderr
        self.assertIn(TEST_TENANT, combined)


# ---------------------------------------------------------------------------
# CLI — scan
# ---------------------------------------------------------------------------

class TestAnchorExplorerCLIScan(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()
        anchor = build_anchor(TEST_TENANT, TEST_REPO, TEST_DATE,
                              make_receipts(2), status="promoted")
        anchor_dir = os.path.join(
            self.base, ".titan-gate", "anchors", TEST_TENANT,
            "{}_{}".format(TEST_TENANT, "test-repo")
        )
        os.makedirs(anchor_dir, exist_ok=True)
        path = os.path.join(anchor_dir, "{}.json".format(TEST_DATE))
        with open(path, "w") as f:
            json.dump(anchor, f)

    def run_cli(self, *args):
        cmd = [sys.executable, "scripts/anchor_explorer.py"] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_scan_exits_zero(self):
        r = self.run_cli("scan", "--dir", self.base)
        self.assertEqual(r.returncode, 0)

    def test_scan_empty_dir_exits_zero(self):
        empty = tempfile.mkdtemp()
        r = self.run_cli("scan", "--dir", empty)
        self.assertEqual(r.returncode, 0)

    def test_scan_output_not_empty(self):
        r = self.run_cli("scan", "--dir", self.base)
        combined = r.stdout + r.stderr
        self.assertGreater(len(combined), 0)

    def test_scan_tenant_filter_exits_zero(self):
        r = self.run_cli("scan", "--dir", self.base, "--tenant", TEST_TENANT)
        self.assertEqual(r.returncode, 0)

    def test_scan_verbose_exits_zero(self):
        r = self.run_cli("scan", "--dir", self.base, "--verbose")
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()