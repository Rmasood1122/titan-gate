"""WO-3 AT-2b: the writer path produces receipts that actually chain.

End-to-end: evaluate() -> persist -> next prev computed from tree ->
second receipt links to first. This is the test that makes the WO-2
verifier claim true for writer-produced data, not just fixtures.
"""
import json

from judge_engine.v1.engine import evaluate
from titan_gate.chain_state import latest_receipt_hash

TEST_KEY = "ab" * 32


def _evaluate_one(tmp_path, pr_number):
    prev = latest_receipt_hash(tmp_path)
    receipt = evaluate(
        artifact="# test artifact\n",
        scope={"files": ["x.py"], "language": "python", "pr_number": pr_number},
        tenant_id="wo3-test",
        repo="titan-gate",
        repo_full_name="test/titan-gate",
        pr_number=pr_number,
        pr_title="wo3 chain test",
        branch="test",
        base_branch="main",
        commit_sha="0" * 40,
        key_hex=TEST_KEY,
        prev_receipt_hash=prev,
    )
    d = tmp_path / receipt["root_date"]
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{receipt['receipt_id']}.json").write_text(
        json.dumps(receipt), encoding="utf-8")
    return receipt


def test_first_receipt_gets_genesis(tmp_path):
    r1 = _evaluate_one(tmp_path, 1)
    assert r1["prev_receipt_hash"] == "GENESIS"


def test_second_receipt_links_to_first(tmp_path):
    r1 = _evaluate_one(tmp_path, 1)
    r2 = _evaluate_one(tmp_path, 2)
    assert r2["prev_receipt_hash"] == r1["receipt_hash"]


def test_third_receipt_extends_head(tmp_path):
    _evaluate_one(tmp_path, 1)
    r2 = _evaluate_one(tmp_path, 2)
    r3 = _evaluate_one(tmp_path, 3)
    assert r3["prev_receipt_hash"] == r2["receipt_hash"]
    assert latest_receipt_hash(tmp_path) == r3["receipt_hash"]
