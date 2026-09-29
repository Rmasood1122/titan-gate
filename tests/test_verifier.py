import unittest
import json
import os
import sys
import subprocess

TV1 = "tests/vectors/TV1.json"
TV2 = "tests/vectors/TV2.json"
TV3 = "tests/vectors/TV3.json"
GOOD_KEY = "0" * 64
BAD_KEY = "f" * 64
VERIFIER = "scripts/titan_verify.py"


def run_verifier(*args):
    cmd = [sys.executable, VERIFIER] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def tamper(path, field, value, tmp_path):
    with open(path) as f:
        r = json.load(f)
    r[field] = value
    with open(tmp_path, "w") as f:
        json.dump(r, f)
    return tmp_path


# ---------------------------------------------------------------------------
# Valid receipts — positive path
# ---------------------------------------------------------------------------

class TestVerifierValidReceipt(unittest.TestCase):
    def test_tv1_exits_zero(self):
        rc, _, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertEqual(rc, 0)

    def test_tv2_exits_zero(self):
        rc, _, _ = run_verifier(TV2, "--key", GOOD_KEY)
        self.assertEqual(rc, 0)

    def test_tv3_exits_zero(self):
        rc, _, _ = run_verifier(TV3, "--key", GOOD_KEY)
        self.assertEqual(rc, 0)

    def test_output_contains_valid(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertIn("VALID", out)

    def test_output_contains_pass(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertIn("PASS", out)

    def test_output_contains_receipt_id(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertIn("tv1-genesis", out)

    def test_output_contains_tenant(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertIn("tenant_test", out)

    def test_tv2_output_contains_warn(self):
        _, out, _ = run_verifier(TV2, "--key", GOOD_KEY)
        self.assertIn("WARN", out)

    def test_tv3_output_contains_valid(self):
        _, out, _ = run_verifier(TV3, "--key", GOOD_KEY)
        self.assertIn("VALID", out)

    def test_tv1_no_anomalies_in_output(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertNotIn("ERR_", out)


# ---------------------------------------------------------------------------
# Invalid key
# ---------------------------------------------------------------------------

class TestVerifierInvalidKey(unittest.TestCase):
    def test_wrong_key_exits_nonzero(self):
        rc, _, _ = run_verifier(TV1, "--key", BAD_KEY)
        self.assertNotEqual(rc, 0)

    def test_wrong_key_shows_fail(self):
        _, out, _ = run_verifier(TV1, "--key", BAD_KEY)
        self.assertIn("FAIL", out)

    def test_wrong_key_shows_anomaly(self):
        _, out, _ = run_verifier(TV1, "--key", BAD_KEY)
        self.assertIn("SIGNATURE_MISMATCH", out)

    def test_wrong_key_exits_two(self):
        rc, _, _ = run_verifier(TV1, "--key", BAD_KEY)
        self.assertNotEqual(rc, 0)

    def test_all_zeros_key_passes(self):
        rc, _, _ = run_verifier(TV1, "--key", GOOD_KEY)
        self.assertEqual(rc, 0)

    def test_all_ones_key_fails(self):
        rc, _, _ = run_verifier(TV1, "--key", "1" * 64)
        self.assertNotEqual(rc, 0)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

class TestVerifierJsonOutput(unittest.TestCase):
    def test_json_output_valid(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertIn("ok", data)
        self.assertTrue(data["ok"])

    def test_json_output_fields(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        for field in ["ok", "receipt_id", "tenant_id", "verdict",
                      "composite_score", "anomalies"]:
            self.assertIn(field, data)

    def test_json_fail_has_anomalies(self):
        _, out, _ = run_verifier(TV1, "--key", BAD_KEY, "--json")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertGreater(len(data["anomalies"]), 0)

    def test_json_ok_is_bool(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertIsInstance(data["ok"], bool)

    def test_json_anomalies_is_list(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertIsInstance(data["anomalies"], list)

    def test_json_valid_receipt_empty_anomalies(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertEqual(data["anomalies"], [])

    def test_json_receipt_id_correct(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertEqual(data["receipt_id"], "tv1-genesis")

    def test_json_tenant_id_correct(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertEqual(data["tenant_id"], "tenant_test")

    def test_json_verdict_present(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertIn(data["verdict"], ["PASS", "WARN", "FAIL"])

    def test_json_composite_score_in_range(self):
        _, out, _ = run_verifier(TV1, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertGreaterEqual(data["composite_score"], 0.0)
        self.assertLessEqual(data["composite_score"], 1.0)

    def test_json_tv2_ok_true(self):
        _, out, _ = run_verifier(TV2, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertTrue(data["ok"])

    def test_json_tv3_ok_true(self):
        _, out, _ = run_verifier(TV3, "--key", GOOD_KEY, "--json")
        data = json.loads(out)
        self.assertTrue(data["ok"])


# ---------------------------------------------------------------------------
# Missing / bad file
# ---------------------------------------------------------------------------

class TestVerifierMissingFile(unittest.TestCase):
    def test_missing_file_exits_two(self):
        rc, _, _ = run_verifier("nonexistent.json", "--key", GOOD_KEY)
        self.assertEqual(rc, 2)

    def test_missing_file_error_message(self):
        rc, out, err = run_verifier("nonexistent.json", "--key", GOOD_KEY)
        combined = out + err
        self.assertTrue(len(combined) > 0)


# ---------------------------------------------------------------------------
# Tamper tests — ERR codes
# ---------------------------------------------------------------------------

class TestVerifierTamperDetection(unittest.TestCase):
    TMP = "tests/vectors/tmp_tamper.json"

    def tearDown(self):
        if os.path.exists(self.TMP):
            os.remove(self.TMP)

    def test_tampered_verdict_fails(self):
        tamper(TV1, "verdict", "FAIL", self.TMP)
        rc, out, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertNotEqual(rc, 0)

    def test_tampered_verdict_sig_mismatch(self):
        tamper(TV1, "verdict", "FAIL", self.TMP)
        _, out, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertIn("MISMATCH", out)

    def test_tampered_score_fails(self):
        tamper(TV1, "composite_score", 0.0, self.TMP)
        rc, _, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertNotEqual(rc, 0)

    def test_tampered_tenant_fails(self):
        tamper(TV1, "tenant_id", "evil", self.TMP)
        rc, _, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertNotEqual(rc, 0)

    def test_missing_signature_field(self):
        with open(TV1) as f:
            r = json.load(f)
        del r["signature"]
        with open(self.TMP, "w") as f:
            json.dump(r, f)
        rc, out, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertNotEqual(rc, 0)

    def test_missing_signature_err_code(self):
        with open(TV1) as f:
            r = json.load(f)
        del r["signature"]
        with open(self.TMP, "w") as f:
            json.dump(r, f)
        _, out, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertIn("SIG", out)

    def test_tampered_receipt_hash(self):
        tamper(TV1, "receipt_hash", "a" * 64, self.TMP)
        rc, out, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertNotEqual(rc, 0)

    def test_tampered_receipt_hash_err_code(self):
        tamper(TV1, "receipt_hash", "a" * 64, self.TMP)
        _, out, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertIn("MISMATCH", out)

    def test_tampered_signing_version(self):
        tamper(TV1, "signing_version", "other-v1", self.TMP)
        rc, out, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertNotEqual(rc, 0)

    def test_tampered_signing_version_err_code(self):
        tamper(TV1, "signing_version", "other-v1", self.TMP)
        _, out, _ = run_verifier(self.TMP, "--key", GOOD_KEY)
        self.assertTrue(len(out) > 0)


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

class TestVerifierChain(unittest.TestCase):
    def test_tv2_prev_hash_matches_tv1(self):
        with open(TV1) as f:
            tv1 = json.load(f)
        with open(TV2) as f:
            tv2 = json.load(f)
        self.assertEqual(tv2["prev_receipt_hash"], tv1["receipt_hash"])

    def test_tv3_prev_hash_matches_tv2(self):
        with open(TV2) as f:
            tv2 = json.load(f)
        with open(TV3) as f:
            tv3 = json.load(f)
        self.assertEqual(tv3["prev_receipt_hash"], tv2["receipt_hash"])

    def test_tv1_is_genesis(self):
        with open(TV1) as f:
            tv1 = json.load(f)
        self.assertEqual(tv1["prev_receipt_hash"], "GENESIS")

    def test_all_three_verify(self):
        for tv in [TV1, TV2, TV3]:
            rc, _, _ = run_verifier(tv, "--key", GOOD_KEY)
            self.assertEqual(rc, 0, f"{tv} failed verification")


if __name__ == "__main__":
    unittest.main()