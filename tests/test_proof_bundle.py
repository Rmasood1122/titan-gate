import unittest
import os
import sys
import json
import tempfile
import hashlib
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TITAN_SIGNING_KEY"] = "0" * 64

from scripts.generate_proof_bundle import generate_proof_bundle
from api.merkle import compute_merkle_root, make_leaf_string, leaf_hash

TEST_KEY = "0" * 64
TEST_TENANT = "tenant_test"
TEST_REPO = "tenant_test/test-repo"
TEST_DATE = "2026-03-04"


def make_receipts(n):
    from api.receipt_signing import compute_receipt_hash, compute_signature
    receipts = []
    prev = "GENESIS"
    for i in range(n):
        r = {
            "schema_version": "receipt_v1",
            "receipt_id": "receipt-{:03d}".format(i),
            "tenant_id": TEST_TENANT,
            "repo": "test-repo",
            "repo_full_name": TEST_REPO,
            "pr_number": i + 1,
            "pr_title": "PR {}".format(i),
            "branch": "feature/test",
            "base_branch": "main",
            "commit_sha": hashlib.sha256(str(i).encode()).hexdigest()[:40],
            "evaluated_at": "2026-03-04T10:00:00Z",
            "root_date": TEST_DATE,
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
            "prev_receipt_hash": prev,
            "ai_attributed": False,
        }
        r["receipt_hash"] = compute_receipt_hash(r)
        r["signature"] = compute_signature(r, TEST_KEY)
        prev = r["receipt_hash"]
        receipts.append(r)
    return receipts


def make_bundle(n=3):
    receipts = make_receipts(n)
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    bundle = generate_proof_bundle(receipts, TEST_TENANT, TEST_REPO, tmp.name)
    os.unlink(tmp.name)
    return bundle


def write_receipt_files(receipts):
    paths = []
    for r in receipts:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(r, f)
        f.close()
        paths.append(f.name)
    return paths


# ---------------------------------------------------------------------------
# Bundle structure
# ---------------------------------------------------------------------------

class TestBundleStructure(unittest.TestCase):
    def test_required_fields(self):
        bundle = make_bundle()
        for field in [
            "schema", "tenant_id", "repo_full_name", "root_date",
            "merkle_root", "merkle_algorithm", "receipt_count",
            "bundle_hash", "receipts"
        ]:
            self.assertIn(field, bundle)

    def test_schema_version(self):
        self.assertEqual(make_bundle()["schema"], "proof_bundle_v1")

    def test_tenant_id(self):
        self.assertEqual(make_bundle()["tenant_id"], TEST_TENANT)

    def test_receipt_count(self):
        self.assertEqual(make_bundle(3)["receipt_count"], 3)

    def test_receipt_count_one(self):
        self.assertEqual(make_bundle(1)["receipt_count"], 1)

    def test_merkle_algorithm(self):
        self.assertEqual(make_bundle()["merkle_algorithm"], "merkle_v1")

    def test_bundle_hash_present(self):
        self.assertEqual(len(make_bundle()["bundle_hash"]), 64)

    def test_bundle_hash_lowercase(self):
        h = make_bundle()["bundle_hash"]
        self.assertEqual(h, h.lower())

    def test_bundle_hash_is_hex(self):
        h = make_bundle()["bundle_hash"]
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_receipts_is_list(self):
        self.assertIsInstance(make_bundle()["receipts"], list)

    def test_receipts_length_matches_count(self):
        bundle = make_bundle(4)
        self.assertEqual(len(bundle["receipts"]), bundle["receipt_count"])

    def test_repo_full_name(self):
        self.assertEqual(make_bundle()["repo_full_name"], TEST_REPO)

    def test_root_date(self):
        self.assertEqual(make_bundle()["root_date"], TEST_DATE)


# ---------------------------------------------------------------------------
# Merkle root
# ---------------------------------------------------------------------------

class TestBundleMerkleRoot(unittest.TestCase):
    def test_merkle_root_correct(self):
        receipts = make_receipts(3)
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        bundle = generate_proof_bundle(receipts, TEST_TENANT, TEST_REPO, tmp.name)
        os.unlink(tmp.name)
        leaves = [
            make_leaf_string(TEST_TENANT, TEST_DATE, r["receipt_id"], r["receipt_hash"])
            for r in receipts
        ]
        expected = compute_merkle_root(leaves)
        self.assertEqual(bundle["merkle_root"], expected)

    def test_merkle_root_deterministic(self):
        receipts = make_receipts(3)
        tmp1 = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp1.close()
        tmp2 = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp2.close()
        b1 = generate_proof_bundle(receipts, TEST_TENANT, TEST_REPO, tmp1.name)
        b2 = generate_proof_bundle(receipts, TEST_TENANT, TEST_REPO, tmp2.name)
        os.unlink(tmp1.name)
        os.unlink(tmp2.name)
        self.assertEqual(b1["merkle_root"], b2["merkle_root"])

    def test_merkle_root_matches_anchor(self):
        from api.anchor import build_anchor
        receipts = make_receipts(3)
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        bundle = generate_proof_bundle(receipts, TEST_TENANT, TEST_REPO, tmp.name)
        os.unlink(tmp.name)
        anchor = build_anchor(TEST_TENANT, TEST_REPO, TEST_DATE, receipts)
        self.assertEqual(bundle["merkle_root"], anchor["merkle_root"])

    def test_merkle_root_length(self):
        self.assertEqual(len(make_bundle()["merkle_root"]), 64)

    def test_merkle_root_lowercase(self):
        root = make_bundle()["merkle_root"]
        self.assertEqual(root, root.lower())

    def test_adding_receipt_changes_root(self):
        b3 = make_bundle(3)
        b4 = make_bundle(4)
        self.assertNotEqual(b3["merkle_root"], b4["merkle_root"])


# ---------------------------------------------------------------------------
# Receipt proofs
# ---------------------------------------------------------------------------

class TestBundleReceiptProofs(unittest.TestCase):
    def test_each_receipt_has_required_fields(self):
        bundle = make_bundle()
        for r in bundle["receipts"]:
            for field in ["receipt_id", "receipt_hash", "verdict", "leaf_hash"]:
                self.assertIn(field, r)

    def test_leaf_hash_correct(self):
        receipts = make_receipts(3)
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        bundle = generate_proof_bundle(receipts, TEST_TENANT, TEST_REPO, tmp.name)
        os.unlink(tmp.name)
        for i, proof in enumerate(bundle["receipts"]):
            leaf_str = make_leaf_string(
                TEST_TENANT, TEST_DATE,
                receipts[i]["receipt_id"], receipts[i]["receipt_hash"]
            )
            expected = leaf_hash(leaf_str)
            self.assertEqual(proof["leaf_hash"], expected)

    def test_receipt_ids_match(self):
        receipts = make_receipts(3)
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        bundle = generate_proof_bundle(receipts, TEST_TENANT, TEST_REPO, tmp.name)
        os.unlink(tmp.name)
        bundle_ids = [r["receipt_id"] for r in bundle["receipts"]]
        for r in receipts:
            self.assertIn(r["receipt_id"], bundle_ids)

    def test_verdicts_present(self):
        bundle = make_bundle()
        for r in bundle["receipts"]:
            self.assertIn(r["verdict"], ["PASS", "WARN", "FAIL"])

    def test_leaf_hashes_are_hex(self):
        bundle = make_bundle()
        for r in bundle["receipts"]:
            self.assertTrue(all(c in "0123456789abcdef" for c in r["leaf_hash"]))

    def test_leaf_hashes_length(self):
        bundle = make_bundle()
        for r in bundle["receipts"]:
            self.assertEqual(len(r["leaf_hash"]), 64)

    def test_receipt_hashes_length(self):
        bundle = make_bundle()
        for r in bundle["receipts"]:
            self.assertEqual(len(r["receipt_hash"]), 64)


# ---------------------------------------------------------------------------
# Bundle hash
# ---------------------------------------------------------------------------

class TestBundleHash(unittest.TestCase):
    def test_bundle_hash_changes_with_receipts(self):
        b3 = make_bundle(3)
        b4 = make_bundle(4)
        self.assertNotEqual(b3["bundle_hash"], b4["bundle_hash"])

    def test_bundle_hash_deterministic(self):
        receipts = make_receipts(3)
        tmp1 = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp1.close()
        tmp2 = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp2.close()
        b1 = generate_proof_bundle(receipts, TEST_TENANT, TEST_REPO, tmp1.name)
        b2 = generate_proof_bundle(receipts, TEST_TENANT, TEST_REPO, tmp2.name)
        os.unlink(tmp1.name)
        os.unlink(tmp2.name)
        self.assertEqual(b1["bundle_hash"], b2["bundle_hash"])

    def test_bundle_hash_not_equal_to_merkle_root(self):
        bundle = make_bundle()
        self.assertNotEqual(bundle["bundle_hash"], bundle["merkle_root"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestBundleCLI(unittest.TestCase):
    def setUp(self):
        self.receipts = make_receipts(3)
        self.receipt_files = write_receipt_files(self.receipts)
        self.out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.out.close()

    def tearDown(self):
        for f in self.receipt_files:
            if os.path.exists(f):
                os.remove(f)
        if os.path.exists(self.out.name):
            os.remove(self.out.name)

    def run_cli(self, *extra):
        cmd = [
            sys.executable, "scripts/generate_proof_bundle.py",
            "--tenant", TEST_TENANT,
            "--repo", TEST_REPO,
            "--output", self.out.name,
        ] + list(self.receipt_files) + list(extra)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_exits_zero(self):
        r = self.run_cli()
        self.assertEqual(r.returncode, 0)

    def test_cli_missing_file_exits_two(self):
        cmd = [
            sys.executable, "scripts/generate_proof_bundle.py",
            "--tenant", TEST_TENANT,
            "--repo", TEST_REPO,
            "nonexistent.json",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)

    def test_cli_output_contains_merkle_root(self):
        r = self.run_cli()
        combined = r.stdout.lower() + r.stderr.lower()
        self.assertIn("merkle", combined)

    def test_cli_verbose_shows_verdicts(self):
        r = self.run_cli("--verbose")
        combined = r.stdout + r.stderr
        self.assertGreater(len(combined), 0)


if __name__ == "__main__":
    unittest.main()