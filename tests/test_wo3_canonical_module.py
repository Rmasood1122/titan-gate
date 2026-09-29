"""WO-3 AT-0: ONE canonical_bytes definition, shared by writer and verifier.

Fails until titan_gate/canonical.py exists and both api.receipt_signing and
titan_gate.verify import from it instead of defining their own copies.
The stale-verify.py incident is why: duplicated definitions can diverge
silently; a single imported symbol cannot.
"""


def test_shared_module_exists():
    from titan_gate.canonical import canonical_bytes, EXCLUSION_FIELDS  # noqa: F401


def test_verifier_uses_shared_definition():
    from titan_gate import canonical, verify
    assert verify.canonical_bytes is canonical.canonical_bytes, \
        "titan_gate/verify.py must import canonical_bytes, not define its own"


def test_writer_uses_shared_definition():
    from api import receipt_signing
    from titan_gate import canonical
    assert receipt_signing.canonical_bytes is canonical.canonical_bytes, \
        "api/receipt_signing.py must import canonical_bytes, not define its own"


def test_exclusion_fields_single_source():
    from api import receipt_signing
    from titan_gate import canonical, verify
    assert verify.EXCLUSION_FIELDS is canonical.EXCLUSION_FIELDS
    assert receipt_signing.EXCLUSION_FIELDS is canonical.EXCLUSION_FIELDS


def test_canonicalization_key_order_independent():
    from titan_gate.canonical import canonical_bytes
    receipt = {"receipt_id": "wo3-at0-0001",
               "body": {"z": 1, "a": [2, 3]},
               "prev_receipt_hash": "GENESIS",
               "sig": "SHOULD-BE-EXCLUDED"}
    reordered = dict(reversed(list(receipt.items())))
    assert canonical_bytes(receipt) == canonical_bytes(reordered)
