import unittest
from api.constants import (
    ENGINE_VERSION, CONTRACT_VERSION, SCORING_FORMULA_VERSION,
    POLICY_VERSION, MERKLE_ALGORITHM, SIGNING_VERSION,
    ANCHOR_SCHEMA, BLOB_STORE_VERSION,
    SCORE_PASS, SCORE_WARN, VERDICT_PASS, VERDICT_WARN, VERDICT_FAIL,
)


class TestVersionConstants(unittest.TestCase):
    def test_engine_version(self):
        self.assertEqual(ENGINE_VERSION, "1.0.0")

    def test_contract_version(self):
        self.assertEqual(CONTRACT_VERSION, "1.0.0")

    def test_scoring_formula_version(self):
        self.assertEqual(SCORING_FORMULA_VERSION, "1.0.0")

    def test_policy_version(self):
        self.assertEqual(POLICY_VERSION, "1.0.0")

    def test_merkle_algorithm(self):
        self.assertEqual(MERKLE_ALGORITHM, "merkle_v1")

    def test_signing_version(self):
        self.assertEqual(SIGNING_VERSION, "hmac-sha256-v1")

    def test_anchor_schema(self):
        self.assertEqual(ANCHOR_SCHEMA, "anchor_v1")

    def test_blob_store_version(self):
        self.assertEqual(BLOB_STORE_VERSION, "postgres_gzip_v1")


class TestVersionConstantTypes(unittest.TestCase):
    def test_engine_version_is_string(self):
        self.assertIsInstance(ENGINE_VERSION, str)

    def test_contract_version_is_string(self):
        self.assertIsInstance(CONTRACT_VERSION, str)

    def test_scoring_formula_version_is_string(self):
        self.assertIsInstance(SCORING_FORMULA_VERSION, str)

    def test_policy_version_is_string(self):
        self.assertIsInstance(POLICY_VERSION, str)

    def test_merkle_algorithm_is_string(self):
        self.assertIsInstance(MERKLE_ALGORITHM, str)

    def test_signing_version_is_string(self):
        self.assertIsInstance(SIGNING_VERSION, str)

    def test_anchor_schema_is_string(self):
        self.assertIsInstance(ANCHOR_SCHEMA, str)

    def test_blob_store_version_is_string(self):
        self.assertIsInstance(BLOB_STORE_VERSION, str)


class TestVersionConstantsNotEmpty(unittest.TestCase):
    def test_engine_version_not_empty(self):
        self.assertGreater(len(ENGINE_VERSION), 0)

    def test_contract_version_not_empty(self):
        self.assertGreater(len(CONTRACT_VERSION), 0)

    def test_scoring_formula_version_not_empty(self):
        self.assertGreater(len(SCORING_FORMULA_VERSION), 0)

    def test_policy_version_not_empty(self):
        self.assertGreater(len(POLICY_VERSION), 0)

    def test_merkle_algorithm_not_empty(self):
        self.assertGreater(len(MERKLE_ALGORITHM), 0)

    def test_signing_version_not_empty(self):
        self.assertGreater(len(SIGNING_VERSION), 0)

    def test_anchor_schema_not_empty(self):
        self.assertGreater(len(ANCHOR_SCHEMA), 0)

    def test_blob_store_version_not_empty(self):
        self.assertGreater(len(BLOB_STORE_VERSION), 0)


class TestVersionConstantFormats(unittest.TestCase):
    def test_engine_version_semver(self):
        self.assertEqual(len(ENGINE_VERSION.split(".")), 3)

    def test_contract_version_semver(self):
        self.assertEqual(len(CONTRACT_VERSION.split(".")), 3)

    def test_scoring_formula_version_semver(self):
        self.assertEqual(len(SCORING_FORMULA_VERSION.split(".")), 3)

    def test_policy_version_semver(self):
        self.assertEqual(len(POLICY_VERSION.split(".")), 3)

    def test_merkle_algorithm_contains_v(self):
        self.assertIn("v", MERKLE_ALGORITHM)

    def test_signing_version_contains_hmac(self):
        self.assertIn("hmac", SIGNING_VERSION)

    def test_signing_version_contains_sha256(self):
        self.assertIn("sha256", SIGNING_VERSION)

    def test_anchor_schema_contains_v(self):
        self.assertIn("v", ANCHOR_SCHEMA)

    def test_blob_store_version_contains_v(self):
        self.assertIn("v", BLOB_STORE_VERSION)


class TestVersionConstantsDistinct(unittest.TestCase):
    def test_engine_version_not_none(self):
        self.assertIsNotNone(ENGINE_VERSION)

    def test_contract_version_not_none(self):
        self.assertIsNotNone(CONTRACT_VERSION)

    def test_merkle_algorithm_distinct_from_signing(self):
        self.assertNotEqual(MERKLE_ALGORITHM, SIGNING_VERSION)

    def test_anchor_schema_distinct_from_blob_store(self):
        self.assertNotEqual(ANCHOR_SCHEMA, BLOB_STORE_VERSION)

    def test_merkle_algorithm_distinct_from_anchor_schema(self):
        self.assertNotEqual(MERKLE_ALGORITHM, ANCHOR_SCHEMA)


class TestScoringThresholds(unittest.TestCase):
    def test_pass_threshold(self):
        self.assertEqual(SCORE_PASS, 0.70)

    def test_warn_threshold(self):
        self.assertEqual(SCORE_WARN, 0.40)

    def test_pass_greater_than_warn(self):
        self.assertGreater(SCORE_PASS, SCORE_WARN)

    def test_warn_greater_than_zero(self):
        self.assertGreater(SCORE_WARN, 0.0)

    def test_pass_less_than_one(self):
        self.assertLess(SCORE_PASS, 1.0)


class TestScoringThresholdTypes(unittest.TestCase):
    def test_score_pass_is_float(self):
        self.assertIsInstance(SCORE_PASS, float)

    def test_score_warn_is_float(self):
        self.assertIsInstance(SCORE_WARN, float)

    def test_score_pass_is_numeric(self):
        self.assertEqual(SCORE_PASS, SCORE_PASS + 0)

    def test_score_warn_is_numeric(self):
        self.assertEqual(SCORE_WARN, SCORE_WARN + 0)


class TestScoringThresholdBoundaries(unittest.TestCase):
    def test_pass_boundary_exact(self):
        self.assertGreaterEqual(0.70, SCORE_PASS)

    def test_warn_boundary_exact(self):
        self.assertGreaterEqual(0.40, SCORE_WARN)

    def test_score_below_warn_is_fail(self):
        self.assertLess(0.39, SCORE_WARN)

    def test_score_at_warn_is_not_fail(self):
        self.assertGreaterEqual(0.40, SCORE_WARN)

    def test_score_at_pass_is_not_warn(self):
        self.assertGreaterEqual(0.70, SCORE_PASS)

    def test_score_between_warn_and_pass_is_warn_zone(self):
        score = 0.55
        self.assertGreaterEqual(score, SCORE_WARN)
        self.assertLess(score, SCORE_PASS)

    def test_score_above_pass_is_pass_zone(self):
        self.assertGreaterEqual(0.85, SCORE_PASS)

    def test_warn_not_equal_to_pass(self):
        self.assertNotEqual(SCORE_WARN, SCORE_PASS)

    def test_gap_between_thresholds(self):
        self.assertGreater(SCORE_PASS - SCORE_WARN, 0)


class TestVerdictConstants(unittest.TestCase):
    def test_verdict_pass(self):
        self.assertEqual(VERDICT_PASS, "PASS")

    def test_verdict_warn(self):
        self.assertEqual(VERDICT_WARN, "WARN")

    def test_verdict_fail(self):
        self.assertEqual(VERDICT_FAIL, "FAIL")

    def test_verdicts_distinct(self):
        self.assertNotEqual(VERDICT_PASS, VERDICT_WARN)
        self.assertNotEqual(VERDICT_PASS, VERDICT_FAIL)
        self.assertNotEqual(VERDICT_WARN, VERDICT_FAIL)


class TestVerdictConstantTypes(unittest.TestCase):
    def test_verdict_pass_is_string(self):
        self.assertIsInstance(VERDICT_PASS, str)

    def test_verdict_warn_is_string(self):
        self.assertIsInstance(VERDICT_WARN, str)

    def test_verdict_fail_is_string(self):
        self.assertIsInstance(VERDICT_FAIL, str)

    def test_verdict_pass_not_empty(self):
        self.assertGreater(len(VERDICT_PASS), 0)

    def test_verdict_warn_not_empty(self):
        self.assertGreater(len(VERDICT_WARN), 0)

    def test_verdict_fail_not_empty(self):
        self.assertGreater(len(VERDICT_FAIL), 0)


class TestVerdictConstantFormats(unittest.TestCase):
    def test_verdict_pass_uppercase(self):
        self.assertEqual(VERDICT_PASS, VERDICT_PASS.upper())

    def test_verdict_warn_uppercase(self):
        self.assertEqual(VERDICT_WARN, VERDICT_WARN.upper())

    def test_verdict_fail_uppercase(self):
        self.assertEqual(VERDICT_FAIL, VERDICT_FAIL.upper())

    def test_verdict_pass_length(self):
        self.assertEqual(len(VERDICT_PASS), 4)

    def test_verdict_warn_length(self):
        self.assertEqual(len(VERDICT_WARN), 4)

    def test_verdict_fail_length(self):
        self.assertEqual(len(VERDICT_FAIL), 4)

    def test_all_verdicts_same_length(self):
        self.assertEqual(len(VERDICT_PASS), len(VERDICT_WARN))
        self.assertEqual(len(VERDICT_WARN), len(VERDICT_FAIL))

    def test_verdicts_form_complete_set(self):
        self.assertEqual(len({VERDICT_PASS, VERDICT_WARN, VERDICT_FAIL}), 3)


class TestConstantRelationships(unittest.TestCase):
    def test_all_version_strings_present(self):
        for v in [ENGINE_VERSION, CONTRACT_VERSION,
                  SCORING_FORMULA_VERSION, POLICY_VERSION]:
            self.assertIsInstance(v, str)
            self.assertGreater(len(v), 0)

    def test_all_verdicts_present(self):
        self.assertEqual(len([VERDICT_PASS, VERDICT_WARN, VERDICT_FAIL]), 3)

    def test_score_thresholds_ordered(self):
        self.assertGreater(SCORE_PASS, SCORE_WARN)
        self.assertGreater(SCORE_WARN, 0.0)
        self.assertLess(SCORE_PASS, 1.0)

    def test_merkle_algorithm_prefix(self):
        self.assertTrue(MERKLE_ALGORITHM.startswith("merkle"))

    def test_signing_version_prefix(self):
        self.assertTrue(SIGNING_VERSION.startswith("hmac"))

    def test_anchor_schema_prefix(self):
        self.assertTrue(ANCHOR_SCHEMA.startswith("anchor"))

    def test_blob_store_version_prefix(self):
        self.assertTrue(BLOB_STORE_VERSION.startswith("postgres"))

    def test_score_pass_is_seventy_percent(self):
        self.assertAlmostEqual(SCORE_PASS, 0.70, places=10)

    def test_score_warn_is_forty_percent(self):
        self.assertAlmostEqual(SCORE_WARN, 0.40, places=10)

    def test_verdict_pass_not_fail(self):
        self.assertNotEqual(VERDICT_PASS, VERDICT_FAIL)

    def test_all_constants_importable(self):
        for c in [ENGINE_VERSION, CONTRACT_VERSION, SCORING_FORMULA_VERSION,
                  POLICY_VERSION, MERKLE_ALGORITHM, SIGNING_VERSION,
                  ANCHOR_SCHEMA, BLOB_STORE_VERSION, SCORE_PASS, SCORE_WARN,
                  VERDICT_PASS, VERDICT_WARN, VERDICT_FAIL]:
            self.assertIsNotNone(c)

    def test_version_major_is_one(self):
        for v in [ENGINE_VERSION, CONTRACT_VERSION,
                  SCORING_FORMULA_VERSION, POLICY_VERSION]:
            self.assertEqual(int(v.split(".")[0]), 1)

    def test_score_midpoint_is_warn_zone(self):
        midpoint = (SCORE_PASS + SCORE_WARN) / 2
        self.assertGreaterEqual(midpoint, SCORE_WARN)
        self.assertLess(midpoint, SCORE_PASS)

    def test_score_range_is_thirty_percent(self):
        self.assertAlmostEqual(SCORE_PASS - SCORE_WARN, 0.30, places=10)

    def test_verdict_set_has_three_members(self):
        self.assertEqual(len({VERDICT_PASS, VERDICT_WARN, VERDICT_FAIL}), 3)

    def test_signing_version_contains_v1(self):
        self.assertIn("v1", SIGNING_VERSION)

    def test_anchor_schema_contains_v1(self):
        self.assertIn("v1", ANCHOR_SCHEMA)

    def test_merkle_algorithm_contains_v1(self):
        self.assertIn("v1", MERKLE_ALGORITHM)

    def test_blob_store_contains_v1(self):
        self.assertIn("v1", BLOB_STORE_VERSION)

    def test_engine_version_minor_is_zero(self):
        self.assertEqual(int(ENGINE_VERSION.split(".")[1]), 0)

    def test_engine_version_patch_is_zero(self):
        self.assertEqual(int(ENGINE_VERSION.split(".")[2]), 0)

    def test_score_pass_greater_than_half(self):
        self.assertGreater(SCORE_PASS, 0.5)

    def test_score_warn_less_than_half(self):
        self.assertLess(SCORE_WARN, 0.5)

    def test_verdict_fail_is_fail(self):
        self.assertEqual(VERDICT_FAIL, "FAIL")

    def test_score_warn_above_thirty(self):
        self.assertGreater(SCORE_WARN, 0.3)

    def test_score_pass_below_ninety(self):
        self.assertLess(SCORE_PASS, 0.9)


if __name__ == "__main__":
    unittest.main()