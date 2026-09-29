"""WO-T2b — Hypothesis property tests on the parser-facing crypto surfaces.

Each surface must be TOTAL: arbitrary input yields either a CONTROLLED
domain error or a clean pass — never an uncontrolled crash (KeyError,
TypeError, AttributeError leaking out). A crash means an attacker-shaped
input hits an unhandled path, and "malformed input fails cleanly and
locatably" is the product's core promise.

History: the {'receipt_type': []} case below crashed verify_trs2_receipt_v2
with an uncontrolled TypeError (unhashable in set-membership) — found by
this probe in one run, invisible to 829 hand-written tests. The property
test guards the whole class, not just that input.
"""
import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.canonical import canonical_bytes, JCSError
from titan_gate.trs2_writer import verify_trs2_receipt_v2, TRS2ReceiptError
from titan_gate.anchor_v2 import verify_anchor_v2_offline, AnchorV2Error

_PUB = Ed25519PrivateKey.generate().public_key()

json_vals = st.recursive(
    st.none() | st.booleans()
    | st.integers(min_value=-10**12, max_value=10**12)
    | st.floats(allow_nan=False, allow_infinity=False) | st.text(max_size=50),
    lambda c: st.lists(c, max_size=5)
    | st.dictionaries(st.text(max_size=20), c, max_size=5),
    max_leaves=25)


@given(v=st.dictionaries(st.text(max_size=20), json_vals, max_size=8))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_canonical_deterministic_and_order_independent(v):
    try:
        a = canonical_bytes(v)
    except JCSError:
        return
    assert canonical_bytes(dict(reversed(list(v.items())))) == a
    assert canonical_bytes(v) == a


@given(receipt=st.dictionaries(
    st.sampled_from(["receipt_type", "event", "gap", "seq", "sig",
                     "prev_receipt_hash", "schema_version", "tenant_id",
                     "chain_id", "unknown_field"]),
    json_vals, max_size=10))
@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
def test_trs2_verify_only_controlled_errors(receipt):
    try:
        verify_trs2_receipt_v2(receipt, _PUB)
    except TRS2ReceiptError:
        pass
    except Exception as e:
        pytest.fail(f"UNCONTROLLED {type(e).__name__} on {receipt!r}: {e}")


@given(rec=json_vals)
@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
def test_anchor_v2_only_controlled_errors(rec):
    try:
        verify_anchor_v2_offline(rec, rekor_log_pubkey=_PUB, tsa_ca_cert_pem=b"")
    except AnchorV2Error:
        pass
    except Exception as e:
        pytest.fail(f"UNCONTROLLED {type(e).__name__} on {rec!r}: {e}")


def test_trs2_verify_rejects_unhashable_receipt_type():
    # Minimal reproducer pinned as an explicit regression (fast, no
    # Hypothesis needed to catch a re-break of this exact case).
    with pytest.raises(TRS2ReceiptError):
        verify_trs2_receipt_v2({"receipt_type": []}, _PUB)
