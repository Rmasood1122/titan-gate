"""WO-3 AT-2a: writers compute prev_receipt_hash from the persisted chain.

Fails until titan_gate/chain_state.py exists. The helper is the ONE way any
writer learns the chain head; callers never assert their own prev.
"""
import json
from pathlib import Path

import pytest


def _write(dirpath: Path, receipt: dict) -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / f"{receipt['receipt_id']}.json").write_text(
        json.dumps(receipt), encoding="utf-8"
    )


def _receipt(rid: str, prev: str) -> dict:
    """Minimal receipt; receipt_hash computed with the real canonicalization."""
    from api.receipt_signing import compute_receipt_hash
    r = {"receipt_id": rid, "prev_receipt_hash": prev}
    r["receipt_hash"] = compute_receipt_hash(r)
    return r


def test_empty_tree_returns_genesis(tmp_path):
    from titan_gate.chain_state import latest_receipt_hash
    assert latest_receipt_hash(tmp_path) == "GENESIS"


def test_single_receipt_returns_its_hash(tmp_path):
    from titan_gate.chain_state import latest_receipt_hash
    r1 = _receipt("r-0001", "GENESIS")
    _write(tmp_path / "2026-08-06", r1)
    assert latest_receipt_hash(tmp_path) == r1["receipt_hash"]


def test_walks_linkage_across_date_dirs(tmp_path):
    from titan_gate.chain_state import latest_receipt_hash
    r1 = _receipt("r-0001", "GENESIS")
    r2 = _receipt("r-0002", r1["receipt_hash"])
    r3 = _receipt("r-0003", r2["receipt_hash"])
    _write(tmp_path / "2026-08-05", r1)
    _write(tmp_path / "2026-08-05", r2)
    _write(tmp_path / "2026-08-06", r3)
    assert latest_receipt_hash(tmp_path) == r3["receipt_hash"]


def test_fork_is_a_hard_error(tmp_path):
    from titan_gate.chain_state import ChainStateError, latest_receipt_hash
    r1 = _receipt("r-0001", "GENESIS")
    fork_a = _receipt("r-000a", r1["receipt_hash"])
    fork_b = _receipt("r-000b", r1["receipt_hash"])
    _write(tmp_path / "2026-08-06", r1)
    _write(tmp_path / "2026-08-06", fork_a)
    _write(tmp_path / "2026-08-06", fork_b)
    with pytest.raises(ChainStateError):
        latest_receipt_hash(tmp_path)


def test_two_genesis_receipts_is_a_hard_error(tmp_path):
    from titan_gate.chain_state import ChainStateError, latest_receipt_hash
    _write(tmp_path / "2026-08-06", _receipt("r-0001", "GENESIS"))
    _write(tmp_path / "2026-08-06", _receipt("r-0002", "GENESIS"))
    with pytest.raises(ChainStateError):
        latest_receipt_hash(tmp_path)
