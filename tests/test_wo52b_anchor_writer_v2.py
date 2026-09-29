"""WO-5.2b red AT — writer emits anchor_v2; degradation disclosed, not silent.

Properties (FR-RCP-2; PROCESS.md §1 — attack, don't presence-check):
  1. Both legs available -> the WRITTEN record round-trips through
     verify_anchor_v2_offline as ANCHORED (writer proven against the
     verifier, not against itself — TG-5).
  2. One leg's seam fails -> a record IS still written, verifies as
     DEGRADED naming the failed leg, and the status file discloses
     which leg failed and why.
  3. BOTH legs fail -> NO record file exists (nothing resembling an
     anchor survives a total failure), ok=False, both errors disclosed.
Failure philosophy inherited from anchor_root v1: external failures
disclose and return; only caller bugs raise.
"""
import json
import os
import pytest
from cryptography.hazmat.primitives import serialization

# D1 red point: anchor_root_v2 does not exist yet.
from titan_gate.anchor_writer import anchor_root_v2

from titan_gate.anchor_v2 import verify_anchor_v2_offline, AnchorV2Error

ANCHOR = ".titan-gate/anchors/Rehanrana11/Rehanrana11_titan-gate/2026-03-06.json"
LOG_PUBKEY = "tests/fixtures/rekor_log_pubkey.pem"
TSA_TOKEN = "tests/fixtures/tsa/response.tsr"
TSA_CA = "tests/fixtures/tsa/freetsa_cacert.pem"


def _fixtures():
    a = json.load(open(ANCHOR, encoding="utf-8"))
    rp = os.path.join(os.path.dirname(ANCHOR),
                      os.path.basename(a["rekor_record_path"].replace("\\", "/")))
    rekor = json.load(open(rp, encoding="utf-8"))
    pub = serialization.load_pem_public_key(open(LOG_PUBKEY, "rb").read())
    token = open(TSA_TOKEN, "rb").read()
    ca_pem = open(TSA_CA, "rb").read()
    return a["merkle_root"], rekor, pub, token, ca_pem


def _seams(rekor, token, fail=()):
    def rekor_fn(root_hash_hex):
        if "rekor" in fail:
            raise RuntimeError("simulated rekor outage")
        return rekor
    def tsa_fn(root_hash_hex):
        if "tsa" in fail:
            raise RuntimeError("simulated tsa outage")
        return token
    return rekor_fn, tsa_fn


def _record_files(out_dir):
    return [f for f in os.listdir(out_dir)
            if f.startswith("anchor_v2_") and f.endswith(".json")]


def test_writer_record_roundtrips_anchored(tmp_path):
    root, rekor, pub, token, ca_pem = _fixtures()
    rekor_fn, tsa_fn = _seams(rekor, token)
    st = anchor_root_v2(root_hash_hex=root, rekor_fn=rekor_fn,
                        tsa_fn=tsa_fn, out_dir=str(tmp_path))
    assert st.ok
    rec = json.load(open(st.record_path, encoding="utf-8"))
    result = verify_anchor_v2_offline(rec, rekor_log_pubkey=pub,
                                      tsa_ca_cert_pem=ca_pem)
    assert result.status == "ANCHORED"
    assert result.legs_verified == {"rekor", "tsa"}


@pytest.mark.parametrize("down", ["tsa", "rekor"])
def test_writer_single_leg_failure_discloses(tmp_path, down):
    root, rekor, pub, token, ca_pem = _fixtures()
    rekor_fn, tsa_fn = _seams(rekor, token, fail=(down,))
    st = anchor_root_v2(root_hash_hex=root, rekor_fn=rekor_fn,
                        tsa_fn=tsa_fn, out_dir=str(tmp_path))
    assert st.ok                      # degraded is still a successful seal
    rec = json.load(open(st.record_path, encoding="utf-8"))
    result = verify_anchor_v2_offline(rec, rekor_log_pubkey=pub,
                                      tsa_ca_cert_pem=ca_pem)
    assert result.status == "DEGRADED"
    assert down in result.missing_legs
    status = json.load(open(os.path.join(str(tmp_path),
                                         "anchor_status.json"),
                            encoding="utf-8"))
    disclosed = json.dumps(status)
    assert down in disclosed          # WHICH leg failed is on disk
    assert "simulated" in disclosed   # and WHY


def test_writer_total_failure_leaves_no_record(tmp_path):
    root, rekor, pub, token, ca_pem = _fixtures()
    rekor_fn, tsa_fn = _seams(rekor, token, fail=("rekor", "tsa"))
    st = anchor_root_v2(root_hash_hex=root, rekor_fn=rekor_fn,
                        tsa_fn=tsa_fn, out_dir=str(tmp_path))
    assert not st.ok
    assert _record_files(str(tmp_path)) == []   # nothing anchor-shaped exists
    status = json.load(open(os.path.join(str(tmp_path),
                                         "anchor_status.json"),
                            encoding="utf-8"))
    s = json.dumps(status)
    assert "rekor" in s and "tsa" in s          # both failures disclosed


def test_writer_rejects_bad_root_as_caller_bug(tmp_path):
    _, rekor, _, token, _ = _fixtures()
    rekor_fn, tsa_fn = _seams(rekor, token)
    with pytest.raises(Exception):
        anchor_root_v2(root_hash_hex="zz-not-hex", rekor_fn=rekor_fn,
                       tsa_fn=tsa_fn, out_dir=str(tmp_path))
