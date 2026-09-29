import unittest
import hashlib
from api.merkle import (
    leaf_hash, node_hash, compute_merkle_root,
    make_leaf_string, EMPTY_HASH, MERKLE_ALGORITHM
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestMerkleConstants(unittest.TestCase):
    def test_empty_hash_value(self):
        expected = hashlib.sha256(b"L|EMPTY").hexdigest()
        self.assertEqual(EMPTY_HASH, expected)

    def test_merkle_algorithm_name(self):
        self.assertEqual(MERKLE_ALGORITHM, "merkle_v1")

    def test_empty_hash_length(self):
        self.assertEqual(len(EMPTY_HASH), 64)

    def test_empty_hash_lowercase(self):
        self.assertEqual(EMPTY_HASH, EMPTY_HASH.lower())

    def test_empty_hash_is_string(self):
        self.assertIsInstance(EMPTY_HASH, str)

    def test_merkle_algorithm_is_string(self):
        self.assertIsInstance(MERKLE_ALGORITHM, str)

    def test_empty_hash_not_all_zeros(self):
        self.assertNotEqual(EMPTY_HASH, "0" * 64)


# ---------------------------------------------------------------------------
# Leaf hash
# ---------------------------------------------------------------------------

class TestLeafHash(unittest.TestCase):
    def test_leaf_hash_deterministic(self):
        h1 = leaf_hash("v1|t1|2026-03-04|r1|abc")
        h2 = leaf_hash("v1|t1|2026-03-04|r1|abc")
        self.assertEqual(h1, h2)

    def test_leaf_hash_prefix(self):
        data = "v1|tenant|2026-03-04|receipt-id|hash"
        expected = hashlib.sha256(b"L|" + data.encode("utf-8")).hexdigest()
        self.assertEqual(leaf_hash(data), expected)

    def test_leaf_hash_different_inputs(self):
        self.assertNotEqual(leaf_hash("a"), leaf_hash("b"))

    def test_leaf_hash_lowercase(self):
        h = leaf_hash("test")
        self.assertEqual(h, h.lower())

    def test_leaf_hash_length(self):
        self.assertEqual(len(leaf_hash("test")), 64)

    def test_leaf_hash_empty_string(self):
        expected = hashlib.sha256(b"L|").hexdigest()
        self.assertEqual(leaf_hash(""), expected)

    def test_leaf_hash_not_equal_to_empty_hash(self):
        self.assertNotEqual(leaf_hash("test"), EMPTY_HASH)

    def test_leaf_hash_is_hex(self):
        h = leaf_hash("test")
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_leaf_hash_unicode(self):
        h = leaf_hash("v1|tëñànt|2026-03-04|r1|abc")
        self.assertEqual(len(h), 64)
        self.assertEqual(h, h.lower())

    def test_leaf_hash_different_from_node_hash(self):
        data = "a" * 64
        lh = leaf_hash(data)
        nh = node_hash(data, data)
        self.assertNotEqual(lh, nh)

    def test_leaf_hash_pipe_separator(self):
        data = "v1|t|2026-03-04|r|h"
        expected = hashlib.sha256(("L|" + data).encode("utf-8")).hexdigest()
        self.assertEqual(leaf_hash(data), expected)

    def test_leaf_hash_long_input(self):
        data = "v1|tenant|2026-03-04|" + "r" * 100 + "|" + "h" * 64
        h = leaf_hash(data)
        self.assertEqual(len(h), 64)


# ---------------------------------------------------------------------------
# Node hash
# ---------------------------------------------------------------------------

class TestNodeHash(unittest.TestCase):
    def test_node_hash_deterministic(self):
        left = "a" * 64
        right = "b" * 64
        self.assertEqual(node_hash(left, right), node_hash(left, right))

    def test_node_hash_prefix(self):
        left = hashlib.sha256(b"left").hexdigest()
        right = hashlib.sha256(b"right").hexdigest()
        expected = hashlib.sha256(
            b"N|" + bytes.fromhex(left) + bytes.fromhex(right)
        ).hexdigest()
        self.assertEqual(node_hash(left, right), expected)

    def test_node_hash_not_commutative(self):
        left = "a" * 64
        right = "b" * 64
        self.assertNotEqual(node_hash(left, right), node_hash(right, left))

    def test_node_hash_lowercase(self):
        left = "a" * 64
        right = "b" * 64
        h = node_hash(left, right)
        self.assertEqual(h, h.lower())

    def test_node_hash_length(self):
        left = "a" * 64
        right = "b" * 64
        self.assertEqual(len(node_hash(left, right)), 64)

    def test_node_hash_is_hex(self):
        left = "a" * 64
        right = "b" * 64
        h = node_hash(left, right)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_node_hash_same_inputs(self):
        h = node_hash("a" * 64, "a" * 64)
        self.assertEqual(len(h), 64)

    def test_node_hash_uses_binary_concat(self):
        left = hashlib.sha256(b"L").hexdigest()
        right = hashlib.sha256(b"R").hexdigest()
        expected = hashlib.sha256(
            b"N|" + bytes.fromhex(left) + bytes.fromhex(right)
        ).hexdigest()
        self.assertEqual(node_hash(left, right), expected)

    def test_node_hash_different_from_leaf_hash(self):
        val = "a" * 64
        self.assertNotEqual(node_hash(val, val), leaf_hash(val))

    def test_node_hash_returns_string(self):
        result = node_hash("a" * 64, "b" * 64)
        self.assertIsInstance(result, str)


# ---------------------------------------------------------------------------
# Compute merkle root
# ---------------------------------------------------------------------------

class TestComputeMerkleRoot(unittest.TestCase):
    def test_empty_tree(self):
        self.assertEqual(compute_merkle_root([]), EMPTY_HASH)

    def test_single_leaf(self):
        leaves = ["v1|t|2026-03-04|r1|h1"]
        root = compute_merkle_root(leaves)
        self.assertEqual(root, leaf_hash(leaves[0]))

    def test_two_leaves(self):
        leaves = ["v1|t|2026-03-04|r1|h1", "v1|t|2026-03-04|r2|h2"]
        root = compute_merkle_root(leaves)
        sorted_leaves = sorted(leaves)
        expected = node_hash(leaf_hash(sorted_leaves[0]), leaf_hash(sorted_leaves[1]))
        self.assertEqual(root, expected)

    def test_deterministic(self):
        leaves = ["leaf1", "leaf2", "leaf3"]
        self.assertEqual(compute_merkle_root(leaves), compute_merkle_root(leaves))

    def test_order_independent(self):
        leaves = ["leaf1", "leaf2", "leaf3"]
        shuffled = ["leaf3", "leaf1", "leaf2"]
        self.assertEqual(compute_merkle_root(leaves), compute_merkle_root(shuffled))

    def test_odd_number_of_leaves(self):
        leaves = ["leaf1", "leaf2", "leaf3"]
        root = compute_merkle_root(leaves)
        self.assertIsInstance(root, str)
        self.assertEqual(len(root), 64)

    def test_root_is_lowercase_hex(self):
        leaves = ["leaf1", "leaf2"]
        root = compute_merkle_root(leaves)
        self.assertEqual(root, root.lower())
        self.assertTrue(all(c in "0123456789abcdef" for c in root))

    def test_four_leaves(self):
        leaves = ["leaf1", "leaf2", "leaf3", "leaf4"]
        root = compute_merkle_root(leaves)
        self.assertEqual(len(root), 64)
        self.assertEqual(root, root.lower())

    def test_four_leaves_deterministic(self):
        leaves = ["leaf1", "leaf2", "leaf3", "leaf4"]
        self.assertEqual(compute_merkle_root(leaves), compute_merkle_root(leaves))

    def test_four_leaves_order_independent(self):
        leaves = ["leaf1", "leaf2", "leaf3", "leaf4"]
        shuffled = ["leaf4", "leaf2", "leaf1", "leaf3"]
        self.assertEqual(compute_merkle_root(leaves), compute_merkle_root(shuffled))

    def test_eight_leaves(self):
        leaves = ["leaf{}".format(i) for i in range(8)]
        root = compute_merkle_root(leaves)
        self.assertEqual(len(root), 64)

    def test_eight_leaves_order_independent(self):
        leaves = ["leaf{}".format(i) for i in range(8)]
        import random
        shuffled = leaves[:]
        random.seed(42)
        random.shuffle(shuffled)
        self.assertEqual(compute_merkle_root(leaves), compute_merkle_root(shuffled))

    def test_sixteen_leaves(self):
        leaves = ["leaf{}".format(i) for i in range(16)]
        root = compute_merkle_root(leaves)
        self.assertEqual(len(root), 64)

    def test_single_leaf_not_equal_to_empty(self):
        leaves = ["v1|t|2026-03-04|r1|h1"]
        self.assertNotEqual(compute_merkle_root(leaves), EMPTY_HASH)

    def test_different_leaves_different_root(self):
        leaves1 = ["leaf1", "leaf2"]
        leaves2 = ["leaf1", "leaf3"]
        self.assertNotEqual(compute_merkle_root(leaves1), compute_merkle_root(leaves2))

    def test_adding_leaf_changes_root(self):
        leaves1 = ["leaf1", "leaf2"]
        leaves2 = ["leaf1", "leaf2", "leaf3"]
        self.assertNotEqual(compute_merkle_root(leaves1), compute_merkle_root(leaves2))

    def test_five_leaves(self):
        leaves = ["leaf{}".format(i) for i in range(5)]
        root = compute_merkle_root(leaves)
        self.assertEqual(len(root), 64)
        self.assertEqual(root, root.lower())

    def test_five_leaves_order_independent(self):
        leaves = ["leaf{}".format(i) for i in range(5)]
        shuffled = list(reversed(leaves))
        self.assertEqual(compute_merkle_root(leaves), compute_merkle_root(shuffled))

    def test_root_is_string(self):
        self.assertIsInstance(compute_merkle_root(["a", "b"]), str)

    def test_large_tree_twenty_leaves(self):
        leaves = ["v1|t|2026-03-04|r{}|{}".format(i, "a" * 64) for i in range(20)]
        root = compute_merkle_root(leaves)
        self.assertEqual(len(root), 64)
        self.assertEqual(root, root.lower())

    def test_real_leaf_strings(self):
        leaves = [
            make_leaf_string("tenant_test", "2026-03-04", "receipt-001", "a" * 64),
            make_leaf_string("tenant_test", "2026-03-04", "receipt-002", "b" * 64),
            make_leaf_string("tenant_test", "2026-03-04", "receipt-003", "c" * 64),
        ]
        root = compute_merkle_root(leaves)
        self.assertEqual(len(root), 64)
        self.assertEqual(root, root.lower())


# ---------------------------------------------------------------------------
# Make leaf string
# ---------------------------------------------------------------------------

class TestMakeLeafString(unittest.TestCase):
    def test_format(self):
        s = make_leaf_string("tenant1", "2026-03-04", "receipt-uuid", "abc" * 21 + "d")
        self.assertTrue(s.startswith("v1|tenant1|2026-03-04|receipt-uuid|"))

    def test_deterministic(self):
        s1 = make_leaf_string("t", "2026-03-04", "r", "h")
        s2 = make_leaf_string("t", "2026-03-04", "r", "h")
        self.assertEqual(s1, s2)

    def test_contains_all_components(self):
        s = make_leaf_string("mytenant", "2026-03-04", "myreceipt", "myhash")
        self.assertIn("mytenant", s)
        self.assertIn("2026-03-04", s)
        self.assertIn("myreceipt", s)
        self.assertIn("myhash", s)

    def test_starts_with_v1(self):
        s = make_leaf_string("t", "2026-03-04", "r", "h")
        self.assertTrue(s.startswith("v1|"))

    def test_pipe_delimited(self):
        s = make_leaf_string("t", "2026-03-04", "r", "h")
        parts = s.split("|")
        self.assertEqual(len(parts), 5)

    def test_first_component_is_v1(self):
        s = make_leaf_string("t", "2026-03-04", "r", "h")
        self.assertEqual(s.split("|")[0], "v1")

    def test_second_component_is_tenant(self):
        s = make_leaf_string("mytenant", "2026-03-04", "r", "h")
        self.assertEqual(s.split("|")[1], "mytenant")

    def test_third_component_is_date(self):
        s = make_leaf_string("t", "2026-03-04", "r", "h")
        self.assertEqual(s.split("|")[2], "2026-03-04")

    def test_fourth_component_is_receipt_id(self):
        s = make_leaf_string("t", "2026-03-04", "myreceipt", "h")
        self.assertEqual(s.split("|")[3], "myreceipt")

    def test_fifth_component_is_hash(self):
        s = make_leaf_string("t", "2026-03-04", "r", "myhash")
        self.assertEqual(s.split("|")[4], "myhash")

    def test_different_tenants_different_strings(self):
        s1 = make_leaf_string("tenant1", "2026-03-04", "r", "h")
        s2 = make_leaf_string("tenant2", "2026-03-04", "r", "h")
        self.assertNotEqual(s1, s2)

    def test_different_dates_different_strings(self):
        s1 = make_leaf_string("t", "2026-03-04", "r", "h")
        s2 = make_leaf_string("t", "2026-03-05", "r", "h")
        self.assertNotEqual(s1, s2)

    def test_different_receipt_ids_different_strings(self):
        s1 = make_leaf_string("t", "2026-03-04", "r1", "h")
        s2 = make_leaf_string("t", "2026-03-04", "r2", "h")
        self.assertNotEqual(s1, s2)

    def test_different_hashes_different_strings(self):
        s1 = make_leaf_string("t", "2026-03-04", "r", "hash1")
        s2 = make_leaf_string("t", "2026-03-04", "r", "hash2")
        self.assertNotEqual(s1, s2)

    def test_leaf_string_produces_consistent_leaf_hash(self):
        s = make_leaf_string("tenant_test", "2026-03-04", "r1", "a" * 64)
        h1 = leaf_hash(s)
        h2 = leaf_hash(s)
        self.assertEqual(h1, h2)


if __name__ == "__main__":
    unittest.main()