"""Pins RFC 8785 unicode behavior confirmed in the Aug 6 diagnostic.

Property: JCS is key-order independent but MUST NOT unicode-normalize.
NFC and NFD encodings of the same visual string are different data and
must yield different canonical bytes. A future normalization "fix"
would silently change every digest ever issued; these pins make that
attempt a red test with a named reason. (TG-9: asserts the property.)
"""
from titan_gate.canonical import canonical_bytes


def test_jcs_key_order_independence():
    assert canonical_bytes({"a": 1, "b": 2}) == canonical_bytes({"b": 2, "a": 1})


def test_jcs_does_not_unicode_normalize():
    nfc = canonical_bytes({"k": "caf\u00e9"})      # é as one codepoint
    nfd = canonical_bytes({"k": "cafe\u0301"})     # e + combining accent
    assert nfc != nfd, "canonicalization must preserve input codepoints, not normalize"
