import unittest
from api.receipt_signing import compute_receipt_hash, compute_signature
from api.replay import replay_verify

TEST_KEY = "0" * 64


def make_valid_receipt(**overrides):
    receipt = {
        "schema_version": "receipt_v1",
        "receipt_id": "test-001",
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
    receipt.update(overrides)
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    receipt["signature"] = compute_signature(receipt, TEST_KEY)
    return receipt


# ---------------------------------------------------------------------------
# Valid receipt
# ---------------------------------------------------------------------------

class TestReplayVerifyValid(unittest.TestCase):
    def test_valid_receipt_ok(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertTrue(result["ok"])

    def test_valid_receipt_no_anomalies(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertEqual(result["anomalies"], [])

    def test_returns_dict(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertIsInstance(result, dict)

    def test_result_has_ok_key(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertIn("ok", result)

    def test_result_has_anomalies_key(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertIn("anomalies", result)

    def test_anomalies_is_list(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertIsInstance(result["anomalies"], list)

    def test_ok_is_bool(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertIsInstance(result["ok"], bool)

    def test_valid_warn_verdict(self):
        r = make_valid_receipt(
            verdict="WARN",
            composite_score=0.55,
            structural_score=0.6,
            semantic_score=0.5,
        )
        result = replay_verify(r, TEST_KEY)
        self.assertTrue(result["ok"])

    def test_valid_fail_verdict(self):
        r = make_valid_receipt(
            verdict="FAIL",
            composite_score=0.2,
            structural_score=0.2,
            semantic_score=0.2,
        )
        result = replay_verify(r, TEST_KEY)
        self.assertTrue(result["ok"])

    def test_valid_with_process_violations(self):
        r = make_valid_receipt(
            process_violations=[{"code": "P1", "description": "test",
                                  "soc2_controls": ["CC6.1"], "severity": "warning"}]
        )
        result = replay_verify(r, TEST_KEY)
        self.assertTrue(result["ok"])

    def test_valid_with_hard_violations(self):
        r = make_valid_receipt(
            verdict="FAIL",
            composite_score=0.1,
            structural_score=0.1,
            semantic_score=0.1,
            hard_violations=[{"code": "H1", "description": "test",
                               "soc2_controls": ["CC8.1"], "severity": "blocking"}]
        )
        result = replay_verify(r, TEST_KEY)
        self.assertTrue(result["ok"])

    def test_valid_chained_receipt(self):
        prev_hash = "e" * 64
        r = make_valid_receipt(prev_receipt_hash=prev_hash)
        result = replay_verify(r, TEST_KEY)
        self.assertTrue(result["ok"])

    def test_valid_ai_attributed_true(self):
        r = make_valid_receipt(ai_attributed=True)
        result = replay_verify(r, TEST_KEY)
        self.assertTrue(result["ok"])


# ---------------------------------------------------------------------------
# Tampered fields
# ---------------------------------------------------------------------------

class TestReplayVerifyTampered(unittest.TestCase):
    def test_tampered_verdict(self):
        r = make_valid_receipt()
        r["verdict"] = "FAIL"
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_verdict_anomaly_type(self):
        r = make_valid_receipt()
        r["verdict"] = "FAIL"
        result = replay_verify(r, TEST_KEY)
        types = [a["type"] for a in result["anomalies"]]
        self.assertIn("RECEIPT_HASH_MISMATCH", types)

    def test_tampered_composite_score(self):
        r = make_valid_receipt()
        r["composite_score"] = 0.0
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_structural_score(self):
        r = make_valid_receipt()
        r["structural_score"] = 0.0
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_semantic_score(self):
        r = make_valid_receipt()
        r["semantic_score"] = 0.0
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_tenant_id(self):
        r = make_valid_receipt()
        r["tenant_id"] = "evil-tenant"
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_pr_number(self):
        r = make_valid_receipt()
        r["pr_number"] = 999
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_commit_sha(self):
        r = make_valid_receipt()
        r["commit_sha"] = "f" * 40
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_artifact_hash(self):
        r = make_valid_receipt()
        r["artifact_hash"] = "0" * 64
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_scope_hash(self):
        r = make_valid_receipt()
        r["scope_hash"] = "0" * 64
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_prev_receipt_hash(self):
        r = make_valid_receipt()
        r["prev_receipt_hash"] = "0" * 64
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_receipt_hash_directly(self):
        r = make_valid_receipt()
        r["receipt_hash"] = "0" * 64
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_receipt_hash_anomaly_type(self):
        r = make_valid_receipt()
        r["receipt_hash"] = "0" * 64
        result = replay_verify(r, TEST_KEY)
        types = [a["type"] for a in result["anomalies"]]
        self.assertIn("RECEIPT_HASH_MISMATCH", types)

    def test_tampered_engine_version(self):
        r = make_valid_receipt()
        r["engine_version"] = "9.9.9"
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_signing_version(self):
        r = make_valid_receipt()
        r["signing_version"] = "other-v1"
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_merkle_algorithm(self):
        r = make_valid_receipt()
        r["merkle_algorithm"] = "merkle_v2"
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_tampered_ai_attributed(self):
        r = make_valid_receipt()
        r["ai_attributed"] = True
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])


# ---------------------------------------------------------------------------
# Wrong key
# ---------------------------------------------------------------------------

class TestReplayWrongKey(unittest.TestCase):
    def test_wrong_key_fails(self):
        r = make_valid_receipt()
        result = replay_verify(r, "f" * 64)
        self.assertFalse(result["ok"])

    def test_wrong_key_anomaly_type(self):
        r = make_valid_receipt()
        result = replay_verify(r, "f" * 64)
        types = [a["type"] for a in result["anomalies"]]
        self.assertIn("SIGNATURE_MISMATCH", types)

    def test_all_zeros_key_different_from_all_ones(self):
        r = make_valid_receipt()
        result_zeros = replay_verify(r, "0" * 64)
        result_ones = replay_verify(r, "1" * 64)
        self.assertTrue(result_zeros["ok"])
        self.assertFalse(result_ones["ok"])

    def test_empty_key_string_fails(self):
        r = make_valid_receipt()
        try:
            result = replay_verify(r, "")
            self.assertFalse(result["ok"])
        except Exception:
            pass  # raising is also acceptable


# ---------------------------------------------------------------------------
# Anomaly structure
# ---------------------------------------------------------------------------

class TestReplayAnomalyStructure(unittest.TestCase):
    def test_anomaly_has_type(self):
        r = make_valid_receipt()
        r["verdict"] = "FAIL"
        result = replay_verify(r, TEST_KEY)
        for anomaly in result["anomalies"]:
            self.assertIn("type", anomaly)

    def test_anomaly_type_is_string(self):
        r = make_valid_receipt()
        r["verdict"] = "FAIL"
        result = replay_verify(r, TEST_KEY)
        for anomaly in result["anomalies"]:
            self.assertIsInstance(anomaly["type"], str)

    def test_multiple_anomalies_on_multi_tamper(self):
        r = make_valid_receipt()
        r["verdict"] = "FAIL"
        r["receipt_hash"] = "0" * 64
        result = replay_verify(r, TEST_KEY)
        self.assertGreaterEqual(len(result["anomalies"]), 1)

    def test_clean_receipt_zero_anomalies(self):
        r = make_valid_receipt()
        result = replay_verify(r, TEST_KEY)
        self.assertEqual(len(result["anomalies"]), 0)

    def test_single_tamper_produces_anomaly(self):
        r = make_valid_receipt()
        r["composite_score"] = 0.99
        result = replay_verify(r, TEST_KEY)
        self.assertGreater(len(result["anomalies"]), 0)

    def test_signature_mismatch_anomaly_present(self):
        r = make_valid_receipt()
        result = replay_verify(r, "f" * 64)
        types = [a["type"] for a in result["anomalies"]]
        self.assertTrue(any("MISMATCH" in t or "SIG" in t for t in types))


# ---------------------------------------------------------------------------
# Missing fields
# ---------------------------------------------------------------------------

class TestReplayMissingFields(unittest.TestCase):
    def test_missing_signature_fails(self):
        r = make_valid_receipt()
        del r["signature"]
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_missing_receipt_hash_fails(self):
        r = make_valid_receipt()
        del r["receipt_hash"]
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_missing_tenant_id_fails(self):
        r = make_valid_receipt()
        del r["tenant_id"]
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])

    def test_missing_verdict_fails(self):
        r = make_valid_receipt()
        del r["verdict"]
        result = replay_verify(r, TEST_KEY)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()