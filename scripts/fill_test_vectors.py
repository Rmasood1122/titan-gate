import json
import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.receipt_signing import compute_receipt_hash, compute_signature
from api.merkle import compute_merkle_root, make_leaf_string

TEST_KEY = "0" * 64
VECTORS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "vectors")

PASS = "[PASS]"
FAIL = "[FAIL]"


def load(name):
    path = os.path.join(VECTORS_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check(label, expected, actual):
    status = PASS if expected == actual else FAIL
    print(status + " " + label)
    if expected != actual:
        print("  expected: " + str(expected))
        print("  actual  : " + str(actual))
    return expected == actual


def main():
    tv1 = load("TV1.json")
    tv2 = load("TV2.json")
    tv3 = load("TV3.json")

    all_pass = True

    print("=" * 60)
    print("TV1 CHECKS")
    print("=" * 60)

    tv1_hash = compute_receipt_hash(tv1)
    tv1_sig = compute_signature(tv1, TEST_KEY)

    all_pass &= check("TV1 receipt_hash", tv1["receipt_hash"], tv1_hash)
    all_pass &= check("TV1 signature", tv1["signature"], tv1_sig)
    all_pass &= check("TV1 prev_receipt_hash is GENESIS", "GENESIS", tv1["prev_receipt_hash"])

    print()
    print("=" * 60)
    print("TV2 CHECKS")
    print("=" * 60)

    tv2_hash = compute_receipt_hash(tv2)
    tv2_sig = compute_signature(tv2, TEST_KEY)

    all_pass &= check("TV2 receipt_hash", tv2["receipt_hash"], tv2_hash)
    all_pass &= check("TV2 signature", tv2["signature"], tv2_sig)
    all_pass &= check("TV2 prev_receipt_hash == TV1 receipt_hash", tv1["receipt_hash"], tv2["prev_receipt_hash"])

    print()
    print("=" * 60)
    print("TV3 CHECKS")
    print("=" * 60)

    tv3_hash = compute_receipt_hash(tv3)
    tv3_sig = compute_signature(tv3, TEST_KEY)

    all_pass &= check("TV3 receipt_hash", tv3["receipt_hash"], tv3_hash)
    all_pass &= check("TV3 signature", tv3["signature"], tv3_sig)
    all_pass &= check("TV3 prev_receipt_hash == TV2 receipt_hash", tv2["receipt_hash"], tv3["prev_receipt_hash"])

    print()
    print("=" * 60)
    print("MERKLE ROOT CHECK")
    print("=" * 60)

    leaves = [
        make_leaf_string(r["tenant_id"], r["root_date"], r["receipt_id"], r["receipt_hash"])
        for r in [tv1, tv2, tv3]
    ]
    merkle_root = compute_merkle_root(leaves)
    print("Merkle root (TV1+TV2+TV3): " + merkle_root)

    print()
    print("=" * 60)
    print("HEX CASE CHECKS")
    print("=" * 60)

    for name, r in [("TV1", tv1), ("TV2", tv2), ("TV3", tv3)]:
        all_pass &= check(name + " receipt_hash lowercase", r["receipt_hash"], r["receipt_hash"].lower())
        all_pass &= check(name + " signature lowercase", r["signature"], r["signature"].lower())

    print()
    print("=" * 60)
    if all_pass:
        print("RESULT: ALL CHECKS PASSED")
    else:
        print("RESULT: ONE OR MORE CHECKS FAILED")
    print("=" * 60)

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
