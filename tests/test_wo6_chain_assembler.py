"""WO-6 AT: ChainAssembler — normalized events -> growing v2 chain,
with FR-ING-6 gap detection derived from the chain itself.

Spec:
  - ChainAssembler(receipts_root, tenant_id, source_id, key_id, sign_fn,
    silence_threshold_s=600). sign_fn=None REFUSES (no key defaults,
    WO-7 ledger). record_poll(poll_time, events) -> list of Path written.
  - prev/seq come ONLY from chain state (chain_state philosophy: callers
    never assert prev). Seq 0/GENESIS exactly once, on an empty tree.
  - Silence: empty poll AND time since last chain activity > threshold
    AND no open gap -> signed open-gap receipt (interval_start = last
    activity). Events after an open gap -> close marker first, then
    actions. THE CHAIN IS THE STATE: open gap = gap receipt with no
    later marker; a restarted assembler discovers it by scan and never
    double-emits.
  - Extending a tampered tree REFUSES (ChainStateError surfaces —
    writing on a broken chain would launder the break).
  - chain_state gains receipt_trs2_v2 recompute + head-seq discovery.
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.chain_state import ChainStateError, latest_receipt_hash
from titan_gate.copilot_normalize import normalize_copilot_record
from titan_gate.ingest_assembler import (   # does not exist yet -> RED
    ChainAssembler,
    AssemblerError,
)

FIXTURES = Path(__file__).parent / "fixtures" / "copilot"


def _record(n: int) -> dict:
    return json.loads((FIXTURES / f"example_{n}_auditdata.json").read_bytes())


@pytest.fixture()
def keys():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture()
def asm(tmp_path, keys):
    priv, _ = keys
    return ChainAssembler(
        receipts_root=tmp_path / "receipts", tenant_id="tenant-1",
        source_id="m365-audit", key_id="k1",
        sign_fn=lambda d: priv.sign(d), silence_threshold_s=600)


def _ev(n: int, ingest_time: str) -> dict:
    return normalize_copilot_record(_record(n), source_id="m365-audit",
                                    ingest_time=ingest_time)


def _chain_receipts(root: Path):
    rs = [json.loads(p.read_text(encoding="utf-8"))
          for p in sorted(root.rglob("*.json"))]
    return sorted(rs, key=lambda r: r["seq"])


def _walk(root: Path, pub) -> int:
    from titan_gate.verify import _verify_chain
    import tempfile, os
    raw = pub.public_bytes_raw().hex()
    fd, pp = tempfile.mkstemp(suffix=".pub")
    os.write(fd, raw.encode()); os.close(fd)
    try:
        return _verify_chain(str(root), None, pp, "json", True)
    finally:
        os.unlink(pp)


T0, T1, T2, T3 = ("2026-08-06T10:00:00+00:00", "2026-08-06T10:05:00+00:00",
                  "2026-08-06T10:20:00+00:00", "2026-08-06T10:30:00+00:00")


# ------------------------------------------------------------ append path

def test_first_action_is_genesis(asm, keys):
    paths = asm.record_poll(T0, [_ev(1, T0)])
    assert len(paths) == 1
    (r,) = _chain_receipts(asm.receipts_root)
    assert r["seq"] == 0 and r["prev_receipt_hash"] == "GENESIS"
    assert r["receipt_type"] == "action"


def test_sequential_prev_is_real_never_genesis(asm, keys):
    """The tombstone for 'production writers stamp GENESIS on every
    receipt' (MASTER_STATE known gap). prev is computed from the actual
    prior receipt, via chain_state, on every append."""
    asm.record_poll(T0, [_ev(1, T0)])
    asm.record_poll(T1, [_ev(2, T1)])
    r0, r1 = _chain_receipts(asm.receipts_root)
    assert r1["seq"] == 1
    assert r1["prev_receipt_hash"] == r0["receipt_hash"] != "GENESIS"


def test_chain_state_supports_v2(asm, keys):
    asm.record_poll(T0, [_ev(1, T0)])
    (r,) = _chain_receipts(asm.receipts_root)
    assert latest_receipt_hash(asm.receipts_root) == r["receipt_hash"]


# ---------------------------------------------------------- gap lifecycle

def test_silence_past_threshold_emits_open_gap(asm):
    asm.record_poll(T0, [_ev(1, T0)])          # activity at 10:00
    asm.record_poll(T2, [])                    # 20 min silent > 600s
    rs = _chain_receipts(asm.receipts_root)
    assert [r["receipt_type"] for r in rs] == ["action", "gap"]
    assert rs[1]["gap"]["source_id"] == "m365-audit"
    assert rs[1]["gap"]["interval_start"] == T0


def test_short_silence_no_gap(asm):
    asm.record_poll(T0, [_ev(1, T0)])
    asm.record_poll(T1, [])                    # 5 min < threshold
    rs = _chain_receipts(asm.receipts_root)
    assert [r["receipt_type"] for r in rs] == ["action"]


def test_recovery_closes_gap_then_appends(asm):
    asm.record_poll(T0, [_ev(1, T0)])
    asm.record_poll(T2, [])                    # open gap
    asm.record_poll(T3, [_ev(2, T3)])          # recovery
    rs = _chain_receipts(asm.receipts_root)
    assert [r["receipt_type"] for r in rs] == ["action", "gap",
                                               "marker", "action"]
    assert rs[2]["gap"]["interval_start"] == T0
    assert rs[2]["gap"]["interval_end"] == T3


def test_silent_polls_never_double_open(asm):
    asm.record_poll(T0, [_ev(1, T0)])
    asm.record_poll(T2, [])
    asm.record_poll(T3, [])                    # still silent, gap open
    rs = _chain_receipts(asm.receipts_root)
    assert [r["receipt_type"] for r in rs] == ["action", "gap"]


def test_restart_discovers_open_gap_from_chain(tmp_path, keys):
    """THE CHAIN IS THE STATE: a fresh assembler over the same tree must
    see the unclosed gap and close it — never emit a second open."""
    priv, _ = keys
    mk = lambda: ChainAssembler(
        receipts_root=tmp_path / "receipts", tenant_id="tenant-1",
        source_id="m365-audit", key_id="k1",
        sign_fn=lambda d: priv.sign(d), silence_threshold_s=600)
    a1 = mk()
    a1.record_poll(T0, [_ev(1, T0)])
    a1.record_poll(T2, [])                     # open gap, then "crash"
    a2 = mk()                                  # restart
    a2.record_poll(T3, [])                     # still silent
    rs = _chain_receipts(tmp_path / "receipts")
    assert [r["receipt_type"] for r in rs] == ["action", "gap"]  # no dupe
    a2.record_poll(T3, [_ev(2, T3)])           # recovery closes THE gap
    rs = _chain_receipts(tmp_path / "receipts")
    assert [r["receipt_type"] for r in rs] == ["action", "gap",
                                               "marker", "action"]


# ------------------------------------------------------- whole-chain truth

def test_assembled_chain_passes_v2_walk(asm, keys):
    _, pub = keys
    asm.record_poll(T0, [_ev(1, T0)])
    asm.record_poll(T2, [])
    asm.record_poll(T3, [_ev(2, T3)])
    assert _walk(asm.receipts_root, pub) == 0


# ------------------------------------------------------------- refusals

def test_no_sign_fn_refuses(tmp_path):
    with pytest.raises((AssemblerError, TypeError, ValueError)):
        ChainAssembler(receipts_root=tmp_path / "r", tenant_id="t",
                       source_id="s", key_id="k", sign_fn=None)


def test_tampered_tree_refuses_extension(asm):
    asm.record_poll(T0, [_ev(1, T0)])
    p = next(iter(sorted(asm.receipts_root.rglob("*.json"))))
    r = json.loads(p.read_text(encoding="utf-8"))
    r["tenant_id"] = "tampered"
    p.write_text(json.dumps(r), encoding="utf-8")
    with pytest.raises(ChainStateError):
        asm.record_poll(T1, [_ev(2, T1)])
