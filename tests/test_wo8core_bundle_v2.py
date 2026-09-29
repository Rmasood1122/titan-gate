"""WO-8-core red AT — bundle_v2: the demo kit a stranger verifies alone.

Properties (FRD AT-18/AT-21 shape; P17 kill; SPEC-2 stabilization trigger):
  1. Self-contained bundle dir: verified from a tmp COPY with only
     titan-verify + bundled pubkey — no repo paths, no network (TG-14
     made mechanical: any path dependence fails the copy step).
  2. Chain preserved: every receipt carries prev_receipt_hash; deleting
     one from the copy -> FAIL naming position (proof_bundle_v1 could not).
  3. Tamper twin ships alongside, FAILS naming position — the demo's
     second command, pinned. Twin differs by EXACTLY one receipt.
  4. Manifest + README machine-state the honest boundary (fixture-derived
     events, vendor-demo key custody) — Rule 3 enforced by test.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# D1 red point: module does not exist yet.
from titan_gate.bundle_v2 import generate_demo_bundle, BundleV2Error


@pytest.fixture(scope="module")
def kit(tmp_path_factory):
    out = tmp_path_factory.mktemp("kit")
    generate_demo_bundle(out_dir=str(out))
    return out


def _copy(src: Path, tmp_path: Path) -> Path:
    dst = tmp_path / src.name
    shutil.copytree(src, dst)
    return dst


REPO_ROOT = Path(__file__).resolve().parents[1]


def _titan_verify(bundle_dir: Path):
    """Invoke the CURRENT packaged CLI (titan_gate.verify:main — the same
    function the titan-verify console script maps to) against the bundle.
    Absolute paths; run from repo root so the repo's code is what runs,
    never a stale installed build. Self-containment is enforced by the
    tmp COPY, not by cwd."""
    # Invoke main() exactly as the titan-verify console script does
    # (pyproject: titan-verify = "titan_gate.verify:main"), bypassing
    # runpy's -m path which collides with an installed copy of the pkg.
    prog = ("import sys; sys.argv = ['titan-verify'] + sys.argv[1:]; "
            "from titan_gate.verify import main; main()")
    cmd = [sys.executable, "-c", prog, "--chain",
           str((bundle_dir / "receipts").resolve()),
           "--pubkey", str((bundle_dir / "pubkey.hex").resolve())]
    env = dict(__import__('os').environ, PYTHONPATH=str(REPO_ROOT))
    return subprocess.run(cmd, capture_output=True, text=True,
                          cwd=str(REPO_ROOT), env=env)


def test_bundle_v2_verifies_offline_from_directory_alone(kit, tmp_path):
    b = _copy(kit / "bundle", tmp_path)
    proc = _titan_verify(b)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rec = json.loads((b / "anchor_v2.json").read_text(encoding="utf-8"))
    assert rec["schema"] == "anchor_v2"
    assert rec["legs"]["rekor"] is not None
    assert rec["legs"]["tsa"] is not None


def test_bundle_v2_preserves_chain_and_names_deletion(kit, tmp_path):
    b = _copy(kit / "bundle", tmp_path)
    receipts = sorted((b / "receipts").glob("*.json"))
    assert len(receipts) >= 5
    for rp in receipts:
        r = json.loads(rp.read_text(encoding="utf-8"))
        assert "prev_receipt_hash" in r          # P17, dead
    receipts[len(receipts) // 2].unlink()
    proc = _titan_verify(b)
    assert proc.returncode != 0
    assert "position" in (proc.stdout + proc.stderr).lower()


def test_bundle_v2_contains_gap_disclosure(kit):
    types = [json.loads(p.read_text(encoding="utf-8"))["receipt_type"]
             for p in sorted((kit / "bundle" / "receipts").glob("*.json"))]
    assert "action" in types
    assert "gap" in types
    assert "marker" in types


def test_tamper_twin_fails_with_position(kit, tmp_path):
    twin = _copy(kit / "bundle_tampered", tmp_path)
    proc = _titan_verify(twin)
    assert proc.returncode != 0
    text = (proc.stdout + proc.stderr).lower()
    assert "position" in text or "seq" in text


def test_tamper_twin_differs_by_exactly_one_receipt(kit):
    a = {p.name: p.read_bytes()
         for p in (kit / "bundle" / "receipts").glob("*.json")}
    b = {p.name: p.read_bytes()
         for p in (kit / "bundle_tampered" / "receipts").glob("*.json")}
    assert set(a) == set(b)
    diffs = [n for n in a if a[n] != b[n]]
    assert len(diffs) == 1


def test_bundle_manifest_states_honest_boundary(kit):
    m = json.loads((kit / "bundle" / "manifest.json")
                   .read_text(encoding="utf-8"))
    assert m["source"] == "fixture-derived"
    assert m["key_custody"] == "vendor-demo"
    readme = (kit / "bundle" / "README-verification.md")\
        .read_text(encoding="utf-8")
    assert "fixture" in readme.lower()
    assert "customer-held keys" in readme.lower()
