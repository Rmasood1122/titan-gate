import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TITAN_SIGNING_KEY"] = "0" * 64

from judge_engine.v1.engine import evaluate

TEST_KEY = "0" * 64

GOOD_ARTIFACT = (
    "import hashlib\n\n"
    "def compute_hash(data: str) -> str:\n"
    "    try:\n"
    "        return hashlib.sha256(data.encode()).hexdigest()\n"
    "    except Exception as e:\n"
    "        raise ValueError(str(e))\n"
)

BAD_ARTIFACT = "x" * 300

BASE_SCOPE = {"language": "python", "files": ["main.py"]}


def make_receipt(artifact=GOOD_ARTIFACT, prev=None, pr_number=1, scope=None):
    return evaluate(
        artifact=artifact,
        tenant_id="tenant_test",
        repo="test-repo",
        repo_full_name="tenant/test-repo",
        pr_number=pr_number,
        pr_title="Test PR",
        branch="feature/test",
        base_branch="main",
        commit_sha="a" * 40,
        scope=scope or BASE_SCOPE,
        prev_receipt_hash=prev or "GENESIS",
        key_hex=TEST_KEY,
    )
# ---------------------------------------------------------------------------
# Output structure
# ---------------------------------------------------------------------------

class TestEngineOutputStructure(unittest.TestCase):
    def test_returns_dict(self):
        self.assertIsInstance(make_receipt(), dict)

    def test_schema_version(self):
        self.assertEqual(make_receipt()["schema_version"], "receipt_v1")

    def test_required_fields_present(self):
        r = make_receipt()
        for field in [
            "schema_version", "receipt_id", "tenant_id", "repo",
            "repo_full_name", "pr_number", "pr_title", "branch",
            "base_branch", "commit_sha", "evaluated_at", "root_date",
            "engine_version", "contract_version", "scoring_formula_version",
            "policy_version", "merkle_algorithm", "signing_version",
            "structural_score", "semantic_score", "composite_score",
            "verdict", "hard_violations", "process_violations",
            "artifact_hash", "scope_hash", "provenance_hash",
            "prev_receipt_hash", "receipt_hash", "signature",
            "ai_attributed", "evaluation_manifest",
        ]:
            self.assertIn(field, r)

    def test_verdict_valid_values(self):
        self.assertIn(make_receipt()["verdict"], ["PASS", "WARN", "FAIL"])

    def test_scores_in_range(self):
        r = make_receipt()
        for field in ["structural_score", "semantic_score", "composite_score"]:
            self.assertGreaterEqual(r[field], 0.0)
            self.assertLessEqual(r[field], 1.0)

    def test_receipt_id_is_string(self):
        r = make_receipt()
        self.assertIsInstance(r["receipt_id"], str)
        self.assertGreater(len(r["receipt_id"]), 0)

    def test_evaluated_at_format(self):
        r = make_receipt()
        self.assertRegex(r["evaluated_at"], r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

    def test_root_date_format(self):
        r = make_receipt()
        self.assertRegex(r["root_date"], r"\d{4}-\d{2}-\d{2}")

    def test_signing_version(self):
        self.assertEqual(make_receipt()["signing_version"], "hmac-sha256-v1")

    def test_merkle_algorithm(self):
        self.assertEqual(make_receipt()["merkle_algorithm"], "merkle_v1")

    def test_tenant_id_preserved(self):
        self.assertEqual(make_receipt()["tenant_id"], "tenant_test")

    def test_repo_preserved(self):
        self.assertEqual(make_receipt()["repo"], "test-repo")

    def test_repo_full_name_preserved(self):
        self.assertEqual(make_receipt()["repo_full_name"], "tenant/test-repo")

    def test_pr_number_preserved(self):
        self.assertEqual(make_receipt()["pr_number"], 1)

    def test_branch_preserved(self):
        self.assertEqual(make_receipt()["branch"], "feature/test")

    def test_base_branch_preserved(self):
        self.assertEqual(make_receipt()["base_branch"], "main")

    def test_commit_sha_preserved(self):
        self.assertEqual(make_receipt()["commit_sha"], "a" * 40)

    def test_hard_violations_is_list(self):
        self.assertIsInstance(make_receipt()["hard_violations"], list)

    def test_process_violations_is_list(self):
        self.assertIsInstance(make_receipt()["process_violations"], list)

    def test_artifact_hash_length(self):
        self.assertEqual(len(make_receipt()["artifact_hash"]), 64)

    def test_scope_hash_length(self):
        self.assertEqual(len(make_receipt()["scope_hash"]), 64)

    def test_provenance_hash_length(self):
        self.assertEqual(len(make_receipt()["provenance_hash"]), 64)

    def test_ai_attributed_is_bool(self):
        self.assertIsInstance(make_receipt()["ai_attributed"], bool)


# ---------------------------------------------------------------------------
# Chaining
# ---------------------------------------------------------------------------

class TestEngineChaining(unittest.TestCase):
    def test_genesis_receipt(self):
        self.assertEqual(make_receipt()["prev_receipt_hash"], "GENESIS")

    def test_chained_receipt(self):
        r1 = make_receipt()
        r2 = make_receipt(prev=r1["receipt_hash"], pr_number=2)
        self.assertEqual(r2["prev_receipt_hash"], r1["receipt_hash"])

    def test_receipt_hash_length(self):
        self.assertEqual(len(make_receipt()["receipt_hash"]), 64)

    def test_signature_length(self):
        self.assertEqual(len(make_receipt()["signature"]), 64)

    def test_receipt_hash_lowercase(self):
        r = make_receipt()
        self.assertEqual(r["receipt_hash"], r["receipt_hash"].lower())

    def test_signature_lowercase(self):
        r = make_receipt()
        self.assertEqual(r["signature"], r["signature"].lower())

    def test_chain_of_three(self):
        r1 = make_receipt(pr_number=1)
        r2 = make_receipt(prev=r1["receipt_hash"], pr_number=2)
        r3 = make_receipt(prev=r2["receipt_hash"], pr_number=3)
        self.assertEqual(r2["prev_receipt_hash"], r1["receipt_hash"])
        self.assertEqual(r3["prev_receipt_hash"], r2["receipt_hash"])

    def test_different_prev_different_signature(self):
        r1 = make_receipt(pr_number=1)
        r2a = make_receipt(prev="GENESIS", pr_number=2)
        r2b = make_receipt(prev=r1["receipt_hash"], pr_number=2)
        self.assertNotEqual(r2a["signature"], r2b["signature"])

    def test_receipt_hash_changes_with_prev(self):
        r1 = make_receipt(prev="GENESIS", pr_number=1)
        r2 = make_receipt(prev="e" * 64, pr_number=1)
        self.assertNotEqual(r1["receipt_hash"], r2["receipt_hash"])


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

class TestEngineScoring(unittest.TestCase):
    def test_good_code_passes(self):
        r = make_receipt(artifact=GOOD_ARTIFACT)
        self.assertIn(r["verdict"], ["PASS", "WARN"])

    def test_composite_score_formula(self):
        r = make_receipt()
        expected = round(0.6 * r["structural_score"] + 0.4 * r["semantic_score"], 4)
        self.assertAlmostEqual(r["composite_score"], expected, places=4)

    def test_hard_violation_forces_fail(self):
        r = make_receipt(artifact=BAD_ARTIFACT)
        if r["hard_violations"]:
            self.assertEqual(r["verdict"], "FAIL")

    def test_pass_threshold(self):
        r = make_receipt(artifact=GOOD_ARTIFACT)
        if r["verdict"] == "PASS":
            self.assertGreaterEqual(r["composite_score"], 0.70)

    def test_warn_threshold(self):
        r = make_receipt(artifact=GOOD_ARTIFACT)
        if r["verdict"] == "WARN":
            self.assertGreaterEqual(r["composite_score"], 0.40)
            self.assertLess(r["composite_score"], 0.70)

    def test_fail_threshold(self):
        r = make_receipt(artifact=GOOD_ARTIFACT)
        if r["verdict"] == "FAIL" and not r["hard_violations"]:
            self.assertLess(r["composite_score"], 0.40)

    def test_structural_score_is_float(self):
        r = make_receipt()
        self.assertIsInstance(r["structural_score"], float)

    def test_semantic_score_is_float(self):
        r = make_receipt()
        self.assertIsInstance(r["semantic_score"], float)

    def test_composite_score_is_float(self):
        r = make_receipt()
        self.assertIsInstance(r["composite_score"], float)

    def test_scores_non_negative(self):
        r = make_receipt()
        self.assertGreaterEqual(r["structural_score"], 0.0)
        self.assertGreaterEqual(r["semantic_score"], 0.0)
        self.assertGreaterEqual(r["composite_score"], 0.0)

    def test_scores_at_most_one(self):
        r = make_receipt()
        self.assertLessEqual(r["structural_score"], 1.0)
        self.assertLessEqual(r["semantic_score"], 1.0)
        self.assertLessEqual(r["composite_score"], 1.0)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

class TestEngineManifest(unittest.TestCase):
    def test_manifest_present(self):
        self.assertIn("evaluation_manifest", make_receipt())

    def test_manifest_fields(self):
        m = make_receipt()["evaluation_manifest"]
        for field in [
            "engine_version", "contract_version", "scoring_formula_version",
            "policy_version", "merkle_algorithm", "signing_version", "evaluated_at"
        ]:
            self.assertIn(field, m)

    def test_manifest_versions_match(self):
        r = make_receipt()
        m = r["evaluation_manifest"]
        self.assertEqual(m["engine_version"], r["engine_version"])
        self.assertEqual(m["merkle_algorithm"], r["merkle_algorithm"])

    def test_manifest_engine_version(self):
        self.assertEqual(make_receipt()["evaluation_manifest"]["engine_version"], "1.0.0")

    def test_manifest_merkle_algorithm(self):
        self.assertEqual(make_receipt()["evaluation_manifest"]["merkle_algorithm"], "merkle_v1")

    def test_manifest_signing_version(self):
        self.assertEqual(make_receipt()["evaluation_manifest"]["signing_version"], "hmac-sha256-v1")

    def test_manifest_evaluated_at_matches_receipt(self):
        r = make_receipt()
        self.assertEqual(r["evaluation_manifest"]["evaluated_at"], r["evaluated_at"])

    def test_manifest_is_dict(self):
        self.assertIsInstance(make_receipt()["evaluation_manifest"], dict)


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

class TestEngineHashes(unittest.TestCase):
    def test_artifact_hash_deterministic(self):
        r1 = make_receipt(artifact=GOOD_ARTIFACT)
        r2 = make_receipt(artifact=GOOD_ARTIFACT)
        self.assertEqual(r1["artifact_hash"], r2["artifact_hash"])

    def test_artifact_hash_changes_with_artifact(self):
        r1 = make_receipt(artifact=GOOD_ARTIFACT)
        r2 = make_receipt(artifact="different code")
        self.assertNotEqual(r1["artifact_hash"], r2["artifact_hash"])

    def test_scope_hash_deterministic(self):
        r1 = make_receipt()
        r2 = make_receipt()
        self.assertEqual(r1["scope_hash"], r2["scope_hash"])

    def test_provenance_hash_deterministic(self):
        r1 = make_receipt()
        r2 = make_receipt()
        self.assertEqual(r1["provenance_hash"], r2["provenance_hash"])

    def test_all_hashes_lowercase(self):
        r = make_receipt()
        for field in ["artifact_hash", "scope_hash", "provenance_hash", "receipt_hash"]:
            self.assertEqual(r[field], r[field].lower())

    def test_all_hashes_hex(self):
        r = make_receipt()
        for field in ["artifact_hash", "scope_hash", "provenance_hash", "receipt_hash"]:
            self.assertTrue(all(c in "0123456789abcdef" for c in r[field]))

    def test_hashes_all_different(self):
        r = make_receipt()
        hashes = [r["artifact_hash"], r["scope_hash"], r["provenance_hash"], r["receipt_hash"]]
        self.assertEqual(len(set(hashes)), len(hashes))