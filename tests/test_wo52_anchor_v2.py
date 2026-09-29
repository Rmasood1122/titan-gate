"""WO-5.2 red AT — anchor_v2: one root, two legs, disclosed degradation.

Properties (STRATEGY_DELTA D1: no bundle ships single-legged; FR-RCP-2:
single-leg loss is disclosed, never silent):
  1. A v2 record verifies BOTH legs offline against the SAME root;
     legs covering different roots FAIL naming both roots.
  2. A record with one leg absent verifies DEGRADED with the missing
     leg named — never as fully anchored, never as a crash.
  3. Both legs absent = FAIL at build time (fail-closed; an anchor to
     nothing is not an anchor). TG-12 class.

Wire truth: Rekor leg = the repo's own live anchor (log_index 2239591431);
TSA leg = real freetsa token over the SAME production root 4933083c....
"""
import json
import os
import pytest
from cryptography.hazmat.primitives import serialization

# D1 red point: this module does not exist yet.
from titan_gate.anchor_v2 import (
    build_anchor_v2_record,
    verify_anchor_v2_offline,
    AnchorV2Error,
)

ANCHOR = ".titan-gate/anchors/Rehanrana11/Rehanrana11_titan-gate/2026-03-06.json"
LOG_PUBKEY = "tests/fixtures/rekor_log_pubkey.pem"
TSA_TOKEN = "tests/fixtures/tsa/response.tsr"
TSA_CA = "tests/fixtures/tsa/freetsa_cacert.pem"


def _load():
    a = json.load(open(ANCHOR, encoding="utf-8"))
    rp = os.path.join(os.path.dirname(ANCHOR),
                      os.path.basename(a["rekor_record_path"].replace("\\", "/")))
    rekor = json.load(open(rp, encoding="utf-8"))
    pub = serialization.load_pem_public_key(open(LOG_PUBKEY, "rb").read())
    token = open(TSA_TOKEN, "rb").read()
    ca_pem = open(TSA_CA, "rb").read()
    return a["merkle_root"], rekor, pub, token, ca_pem


def test_anchor_v2_carries_both_legs_over_one_root():
    root, rekor, pub, token, ca_pem = _load()
    rec = build_anchor_v2_record(root_hash_hex=root, rekor_record=rekor,
                                 tsa_token=token)
    result = verify_anchor_v2_offline(rec, rekor_log_pubkey=pub,
                                      tsa_ca_cert_pem=ca_pem)
    assert result.status == "ANCHORED"
    assert result.legs_verified == {"rekor", "tsa"}


def test_anchor_v2_leg_root_mismatch_fails_naming_both_roots():
    # Record claims a root neither leg actually covers: internal
    # coherence check must FAIL and name both the claimed and the
    # covered root — position, not just failure.
    root, rekor, pub, token, ca_pem = _load()
    wrong = ("0" if root[0] != "0" else "1") + root[1:]
    rec = build_anchor_v2_record(root_hash_hex=wrong, rekor_record=rekor,
                                 tsa_token=token)
    with pytest.raises(AnchorV2Error) as e:
        verify_anchor_v2_offline(rec, rekor_log_pubkey=pub,
                                 tsa_ca_cert_pem=ca_pem)
    msg = str(e.value)
    assert root in msg and wrong in msg


@pytest.mark.parametrize("absent", ["tsa", "rekor"])
def test_anchor_v2_single_leg_degradation_disclosed(absent):
    root, rekor, pub, token, ca_pem = _load()
    kw = dict(root_hash_hex=root, rekor_record=rekor, tsa_token=token)
    kw["rekor_record" if absent == "rekor" else "tsa_token"] = None
    rec = build_anchor_v2_record(**kw)
    result = verify_anchor_v2_offline(rec, rekor_log_pubkey=pub,
                                      tsa_ca_cert_pem=ca_pem)
    assert result.status == "DEGRADED"          # distinct verdict, not a bool
    assert absent in result.missing_legs        # missing leg NAMED
    assert result.status != "ANCHORED"


def test_anchor_v2_degraded_present_leg_still_verified(monkeypatch=None):
    # Degradation discloses the missing leg but the PRESENT leg must
    # still be cryptographically verified — degraded-with-a-broken-leg
    # is FAIL, not DEGRADED. Attack: tamper the token, drop rekor.
    root, rekor, pub, token, ca_pem = _load()
    bad = bytes(token); bad = bad[:-1] + bytes([bad[-1] ^ 0x01])
    rec = build_anchor_v2_record(root_hash_hex=root, rekor_record=None,
                                 tsa_token=bad)
    with pytest.raises(AnchorV2Error):
        verify_anchor_v2_offline(rec, rekor_log_pubkey=pub,
                                 tsa_ca_cert_pem=ca_pem)


def test_anchor_v2_no_legs_fails_closed():
    root, *_ = _load()
    with pytest.raises(AnchorV2Error):
        build_anchor_v2_record(root_hash_hex=root, rekor_record=None,
                               tsa_token=None)
