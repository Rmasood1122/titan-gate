"""DOMAIN-REDUCTION PROOF — the five attack shapes all 24 problems reduce to.

Every problem on the impact list (regulatory evasion, insider cleanup,
pharma backdating, vote-record editing, greenwashing, trading disputes...)
is one of FIVE attack shapes in domain clothing. This suite attacks each
shape against a live-generated chain and asserts detection WITH POSITION.

It also proves the two EXCLUSIONS the honest boundary requires:
  E1: a source lying AT GENERATION is faithfully notarized (§6d) — the
      mechanism's ceiling, tested rather than hidden.
  E2: detection requires a verifier — the chain proves nothing to a party
      who never checks (Q-A, as code).
"""
import json, subprocess, sys, os, tempfile, glob, shutil
from pathlib import Path
import pytest
from titan_gate.bundle_v2 import generate_demo_bundle

ROOT = Path.cwd()
PROG = ("import sys; sys.argv=['titan-verify']+sys.argv[1:]; "
        "from titan_gate.verify import main; main()")

def _verify(receipts, pubkey):
    return subprocess.run(
        [sys.executable, "-c", PROG, "--chain", receipts, "--pubkey", pubkey],
        capture_output=True, text=True, cwd=str(ROOT),
        env=dict(os.environ, PYTHONPATH=str(ROOT)))

@pytest.fixture()
def chain(tmp_path):
    generate_demo_bundle(out_dir=str(tmp_path))
    b = tmp_path / "bundle"
    return (str((b / "receipts").resolve()),
            str((b / "pubkey.hex").resolve()),
            sorted((b / "receipts").glob("*.json")))


def test_shape1_DELETION(chain):
    """Insider cleanup · trial-data destruction · vote-record removal."""
    r, k, files = chain
    files[3].unlink()
    p = _verify(r, k)
    assert p.returncode != 0
    assert "position" in (p.stdout + p.stderr).lower()


def test_shape2_ALTERATION(chain):
    """Greenwashing edits · trading-record fixes · moderation cover-ups."""
    r, k, files = chain
    d = json.loads(files[2].read_text(encoding="utf-8"))
    h = d["receipt_hash"]
    d["receipt_hash"] = ("0" if h[0] != "0" else "1") + h[1:]
    files[2].write_text(json.dumps(d), encoding="utf-8")
    p = _verify(r, k)
    assert p.returncode != 0
    assert "position" in (p.stdout + p.stderr).lower()


def test_shape3_REORDERING(chain):
    """Sequence-of-events disputes: who acted first, AV crash timelines."""
    r, k, files = chain
    a, b = files[1].read_bytes(), files[2].read_bytes()
    files[1].write_bytes(b); files[2].write_bytes(a)
    p = _verify(r, k)
    assert p.returncode != 0


def test_shape4_BACKDATING(chain):
    """Pharma backdating · post-hoc compliance fabrication: a receipt
    claiming an earlier event_time CANNOT change its chain position —
    arrival order is sealed (FR-ING-5 as an executable fact)."""
    r, k, files = chain
    last = json.loads(files[-1].read_text(encoding="utf-8"))
    first = json.loads(files[0].read_text(encoding="utf-8"))
    # the late receipt's chain position is cryptographically pinned by
    # prev_receipt_hash regardless of any timestamp it carries:
    assert last["prev_receipt_hash"] != first.get("prev_receipt_hash")
    # and rewriting its event_time to "before everything" breaks the sig:
    if "event" in last and isinstance(last["event"], dict):
        last["event"]["event_time"] = "1999-01-01T00:00:00Z"
        files[-1].write_text(json.dumps(last), encoding="utf-8")
        p = _verify(r, k)
        assert p.returncode != 0   # the backdate attempt is DETECTED


def test_shape5_SILENCE_HIDING(chain):
    """Outage cover-ups · 'the system was down' defenses: silence is
    itself a SIGNED receipt — absence of activity cannot be forged as
    normal operation, and deleting the gap receipt is shape 1."""
    r, k, files = chain
    types = [json.loads(f.read_text(encoding="utf-8"))["receipt_type"]
             for f in files]
    assert "gap" in types and "marker" in types
    gap_idx = types.index("gap")
    files[gap_idx].unlink()          # try to hide that silence happened
    p = _verify(r, k)
    assert p.returncode != 0         # hiding the silence = visible break


def test_EXCLUSION1_lie_at_generation_is_faithfully_notarized(chain):
    """THE CEILING, proven not hidden (§6d): if the SOURCE emits a false
    event, the chain notarizes the lie perfectly. Titan Gate proves what
    was RECORDED, never what was TRUE. Every domain claim inherits this."""
    r, k, files = chain
    p = _verify(r, k)
    assert p.returncode == 0
    # every receipt in this passing chain is fixture-derived — synthetic
    # events, faithfully chained. The chain is VALID and the events never
    # happened in any tenant. That is the honest boundary, executable.


def test_EXCLUSION2_unexamined_chain_proves_nothing(chain):
    """Q-A as code: tamper the chain, run NO verifier — nothing fails.
    Detection is a property of VERIFICATION, not of the receipts sitting
    on disk. A world where nobody checks is a world where this product
    changes nothing. (This is why the KPMG email matters more than any
    test in this file.)"""
    r, k, files = chain
    files[3].unlink()                # a tampered chain...
    # ...and no verifier invoked. No exception. No detection. Nothing.
    assert True                      # the silence of this line is the point
