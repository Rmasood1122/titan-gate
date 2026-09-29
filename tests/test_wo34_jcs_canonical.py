"""WO-3.4b AT — JCS (RFC 8785) canonicalization for TRS-2.

Scope pin (normative for SPEC.md v2): TRS-2 admits no floats; the
serializer rejects non-integer numbers and integers outside +/-(2^53-1).
Within that domain, output is byte-identical to full RFC 8785 JCS.

TRS-1's sorted-keys canonicalization is golden-pinned elsewhere and
MUST NOT be touched by this work — this file only exercises the new
function, canonical_bytes_jcs().

Expected state on first run: RED (ImportError).
"""
import pytest

from titan_gate.canonical import canonical_bytes_jcs, JCSError


# --- 1. Golden byte vectors ---

def test_golden_simple_object():
    obj = {"b": 2, "a": "x", "c": True, "d": None}
    assert canonical_bytes_jcs(obj) == b'{"a":"x","b":2,"c":true,"d":null}'


def test_golden_nested_and_arrays():
    obj = {"z": [1, "two", {"y": False, "x": []}], "a": {}}
    assert canonical_bytes_jcs(obj) == \
        b'{"a":{},"z":[1,"two",{"x":[],"y":false}]}'


def test_golden_no_whitespace_anywhere():
    out = canonical_bytes_jcs({"k": [1, 2], "j": {"i": "v"}})
    assert b" " not in out and b"\n" not in out


# --- 2. String escaping per RFC 8785 s3.2.2.2 ---

def test_escaping_shorthands_and_control_chars():
    obj = {"s": "\" \\ \b \f \n \r \t \u0000 \u001f"}
    assert canonical_bytes_jcs(obj) == \
        b'{"s":"\\" \\\\ \\b \\f \\n \\r \\t \\u0000 \\u001f"}'


def test_non_ascii_emitted_literally_utf8():
    # ensure_ascii must be off: U+20AC euro sign is 3 UTF-8 bytes, unescaped
    assert canonical_bytes_jcs({"e": "\u20ac"}) == \
        b'{"e":"' + "\u20ac".encode("utf-8") + b'"}'


def test_del_char_not_escaped():
    # JCS escapes only < 0x20 (plus quote/backslash); U+007F stays literal
    assert canonical_bytes_jcs({"d": "\u007f"}) == \
        b'{"d":"' + b"\x7f" + b'"}'


# --- 3. Key ordering: UTF-16 code units, not codepoints ---

def test_key_sort_utf16_non_bmp_before_private_use():
    # U+1D11E (non-BMP, surrogates D834 DD1E) < U+E000 in UTF-16 order,
    # though U+1D11E > U+E000 by codepoint. Python's default str sort
    # gets this WRONG; JCS requires the UTF-16 order.
    obj = {"\ue000": 1, "\U0001d11e": 2}
    out = canonical_bytes_jcs(obj)
    assert out.index("\U0001d11e".encode("utf-8")) < \
           out.index("\ue000".encode("utf-8"))


def test_key_sort_ascii_ordinary():
    out = canonical_bytes_jcs({"10": 1, "1": 2, "A": 3, "a": 4})
    assert out == b'{"1":2,"10":1,"A":3,"a":4}'


# --- 4. Domain restriction: floats and unsafe ints are schema errors ---

@pytest.mark.parametrize("bad", [1.5, 0.1, float("nan"), float("inf"), -0.0])
def test_floats_rejected(bad):
    with pytest.raises(JCSError):
        canonical_bytes_jcs({"n": bad})


@pytest.mark.parametrize("bad", [2**53, -(2**53), 2**60])
def test_ints_outside_ieee_safe_range_rejected(bad):
    with pytest.raises(JCSError):
        canonical_bytes_jcs({"n": bad})


def test_safe_int_boundaries_accepted():
    assert canonical_bytes_jcs({"n": 2**53 - 1}) == b'{"n":9007199254740991}'
    assert canonical_bytes_jcs({"n": -(2**53 - 1)}) == b'{"n":-9007199254740991}'


@pytest.mark.parametrize("bad", [b"bytes", {1: "int-key"}, ("tu", "ple"), set()])
def test_non_json_types_rejected(bad):
    with pytest.raises(JCSError):
        canonical_bytes_jcs({"v": bad} if not isinstance(bad, dict) else bad)


# --- 5. Determinism sanity ---

def test_insertion_order_never_leaks():
    a = canonical_bytes_jcs({"x": 1, "y": 2})
    b_ = canonical_bytes_jcs({"y": 2, "x": 1})
    assert a == b_
