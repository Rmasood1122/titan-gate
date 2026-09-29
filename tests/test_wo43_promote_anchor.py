"""WO-4.3 part 2b AT — promote a sealed daily anchor to Rekor.

promote_anchor(anchor_path, sign_fn, public_key_pem, base_url) reads
the local anchor_v1 file, submits its merkle_root via anchor_root
(mocked with the LIVE fixture), and mutates the anchor in place:

  success: status pending->anchored, anchored_at set (int epoch),
           rekor_record_path set, payload_hash RECOMPUTED (promotion
           adds fields; a stale payload_hash is silent corruption)
  failure: status STAYS pending, anchor_failure={error,timestamp}
           recorded, payload_hash recomputed; sealing/promotion never
           raises on EXTERNAL failure
  idempotent: promoting an already-anchored anchor is a no-op
  caller bug (missing file, malformed anchor): RAISES

Expected first run: RED (no promote_anchor in scripts.seal_daily_root).
"""
import hashlib
import json
import os
import pytest
from unittest import mock

from api.anchor import build_anchor, compute_anchor_payload_hash
from scripts.seal_daily_root import promote_anchor

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
LIVE_ROOT_HEX = hashlib.sha256(b"titan-gate-wo42b-live-probe").hexdigest()

def _fixture_response():
    with open(os.path.join(FIX, "live_anchor_entry.json"), encoding="utf-8") as f:
        return json.load(f)

def _mock_ok():
    m = mock.MagicMock()
    m.read.return_value = json.dumps(_fixture_response()).encode()
    m.__enter__ = lambda s: s
    m.__exit__ = mock.MagicMock(return_value=False)
    return m

def _fake_sign(digest: bytes) -> bytes:
    assert isinstance(digest, bytes) and len(digest) == 32
    return b"\x30\x44" + b"\x01" * 68  # DER-shaped stand-in; mocked network

def _write_anchor(tmp_path, merkle_root=None):
    """Build a real anchor via build_anchor, optionally forcing the
    merkle_root to the live probe's hash so artifact binding can be
    exercised, then recompute payload_hash to keep it honest."""
    receipts = [{"receipt_id": "r1", "receipt_hash": "a" * 64}]
    anchor = build_anchor("tenant-t", "o/repo", "2026-08-07", receipts)
    if merkle_root:
        anchor["merkle_root"] = merkle_root
        anchor.pop("payload_hash")
        anchor["payload_hash"] = compute_anchor_payload_hash(anchor)
    p = tmp_path / "2026-08-07.json"
    p.write_text(json.dumps(anchor, indent=2), encoding="utf-8")
    return str(p)


def test_success_promotes_and_recomputes_payload_hash(tmp_path):
    path = _write_anchor(tmp_path, merkle_root=LIVE_ROOT_HEX)
    with mock.patch("titan_gate.rekor_client.urlopen", return_value=_mock_ok()):
        result = promote_anchor(anchor_path=path, sign_fn=_fake_sign,
                                public_key_pem="-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n",
                                base_url="https://rekor.example")
    a = json.loads(open(path, encoding="utf-8").read())
    assert result.ok is True
    assert a["status"] == "anchored"
    assert isinstance(a["anchored_at"], int) and a["anchored_at"] > 0
    assert a["rekor_record_path"] and os.path.exists(a["rekor_record_path"])
    assert "anchor_failure" not in a
    # the load-bearing pin: payload_hash matches the MUTATED anchor
    assert a["payload_hash"] == compute_anchor_payload_hash(a)

def test_failure_keeps_pending_records_disclosure(tmp_path):
    import urllib.error
    path = _write_anchor(tmp_path, merkle_root=LIVE_ROOT_HEX)
    with mock.patch("titan_gate.rekor_client.urlopen",
                    side_effect=urllib.error.URLError("down")):
        result = promote_anchor(anchor_path=path, sign_fn=_fake_sign,
                                public_key_pem="-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n",
                                base_url="https://rekor.example")
    a = json.loads(open(path, encoding="utf-8").read())
    assert result.ok is False
    assert a["status"] == "pending"
    assert a["anchored_at"] is None
    assert a["anchor_failure"]["error"] and a["anchor_failure"]["timestamp"]
    assert a["payload_hash"] == compute_anchor_payload_hash(a)

def test_promotion_is_idempotent(tmp_path):
    path = _write_anchor(tmp_path, merkle_root=LIVE_ROOT_HEX)
    with mock.patch("titan_gate.rekor_client.urlopen", return_value=_mock_ok()) as u:
        promote_anchor(anchor_path=path, sign_fn=_fake_sign,
                       public_key_pem="-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n",
                       base_url="https://rekor.example")
        first_calls = u.call_count
        result2 = promote_anchor(anchor_path=path, sign_fn=_fake_sign,
                                 public_key_pem="-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n",
                                 base_url="https://rekor.example")
    assert result2.ok is True
    assert u.call_count == first_calls  # no second submission

def test_missing_anchor_file_raises(tmp_path):
    with pytest.raises(Exception):
        promote_anchor(anchor_path=str(tmp_path / "nope.json"),
                       sign_fn=_fake_sign, public_key_pem="x",
                       base_url="https://rekor.example")

def test_malformed_anchor_raises_not_discloses(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"schema": "anchor_v1"}), encoding="utf-8")
    with pytest.raises(Exception):
        promote_anchor(anchor_path=str(p), sign_fn=_fake_sign,
                       public_key_pem="x", base_url="https://rekor.example")


# --- Regression: script-mode execution (NameError class, found live) ---

def test_all_defs_precede_main_guard():
    """promote_anchor was appended BELOW `if __name__: main()` — imports
    define everything before tests run, so import-based tests passed
    while script execution NameError'd at the call site. Pin: every
    def precedes the guard."""
    src = open("scripts/seal_daily_root.py", encoding="utf-8").read()
    guard = src.find('if __name__ == "__main__":')
    assert guard != -1
    import re
    for m in re.finditer(r"^def (\w+)", src, re.M):
        assert m.start() < guard, f"def {m.group(1)} is below the main guard"

def test_script_mode_smoke_no_nameerror(tmp_path):
    """Run the script AS A SCRIPT (subprocess): --promote without
    --anchor-key must exit 2 with the no-key-defaults message — which
    requires reaching the promote branch, past where the NameError
    fired. No network involved on this path."""
    import subprocess, sys
    r = subprocess.run(
        [sys.executable, "scripts/seal_daily_root.py",
         "--tenant", "t", "--repo", "o/r", "--date", "2099-01-01",
         "--receipts-dir", str(tmp_path), "--dir", str(tmp_path),
         "--promote"],
        capture_output=True, text=True)
    assert r.returncode == 2, f"rc={r.returncode} err={r.stderr[:200]}"
    assert "anchor-key" in r.stdout
    assert "NameError" not in r.stderr
