import hashlib
import hmac as _hmac
import json
from typing import Any, Dict

SIGNING_VERSION = "hmac-sha256-v1"
from titan_gate.canonical import EXCLUSION_FIELDS, canonical_bytes  # noqa: F401


def compute_receipt_hash(receipt: Dict[str, Any]) -> str:
    cb = canonical_bytes(receipt)
    return hashlib.sha256(cb).hexdigest()


def compute_signature(receipt: Dict[str, Any], key_hex: str) -> str:
    cb = canonical_bytes(receipt)
    key = bytes.fromhex(key_hex)
    return _hmac.new(key, cb, hashlib.sha256).hexdigest()


def verify_signature(receipt: Dict[str, Any], key_hex: str) -> bool:
    expected = compute_signature(receipt, key_hex)
    actual = receipt.get("signature", "")
    return _hmac.compare_digest(expected, actual)
