"""WO-1: Asymmetric receipt signing for TRS-2 (signing_version: ed25519-v1).

Design (MASTER_STATE §3/§4):
  - Reuses Titan Gate's PROVEN canonical_bytes (full-body hashing, explicit
    exclusion set) — the correctness core stays untouched.
  - Ed25519 (RFC 8032) via `cryptography`: sign with private key, verify with
    PUBLIC key only. Kills G1 (verify-implies-forge under shared HMAC).
  - signing_version is written INTO the body BEFORE signing, so it is covered
    by the signature: downgrade to the legacy scheme is detectable.
  - Legacy hmac-sha256-v1 receipts remain the concern of api/receipt_signing.py;
    this module is additive. Nothing in the 555-test suite is modified.

Standing rule §5.1: the PRIVATE key must ultimately live in the customer trust
domain (WO-7 container). This module never persists keys itself; the keygen CLI
writes them only where the operator points it, mode 0600.
"""
from __future__ import annotations

import argparse
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:  # repo-root imports (pytest from root)
    from api.receipt_signing import canonical_bytes
except ImportError:  # api/ already on sys.path
    from receipt_signing import canonical_bytes

SIGNING_V1_HMAC = "hmac-sha256-v1"
SIGNING_V2_ED25519 = "ed25519-v1"

_RAW = serialization.Encoding.Raw
_PRIV_FMT = serialization.PrivateFormat.Raw
_PUB_FMT = serialization.PublicFormat.Raw
_NO_ENC = serialization.NoEncryption()


class VerificationError(Exception):
    """Raised when a receipt fails cryptographic verification. The message
    names the receipt_id so chain tooling (WO-2) can report positions."""


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex), 32 raw bytes each, hex-encoded."""
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(_RAW, _PRIV_FMT, _NO_ENC).hex()
    pub_hex = priv.public_key().public_bytes(_RAW, _PUB_FMT).hex()
    return priv_hex, pub_hex


class Ed25519Signer:
    """Holds the private key. In production this object lives ONLY inside the
    customer-domain signing container (WO-7); the evidence core never
    instantiates it. Tests and the keygen CLI are the sole in-repo users."""

    def __init__(self, private_key_hex: str):
        self._key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))

    def sign(self, receipt: dict) -> dict:
        """Return a signed copy: signing_version set inside the body, signature
        computed over canonical_bytes of that body (signature itself excluded
        by Titan Gate's EXCLUSION_FIELDS)."""
        body = dict(receipt)
        body["signing_version"] = SIGNING_V2_ED25519
        body.pop("signature", None)
        body["signature"] = self._key.sign(canonical_bytes(body)).hex()
        return body

    def public_key_hex(self) -> str:
        return self._key.public_key().public_bytes(_RAW, _PUB_FMT).hex()


def verify_ed25519(receipt: dict, public_key_hex: str) -> bool:
    """Verify with the PUBLIC key only. Raises VerificationError on any failure;
    returns True on success (mirrors titan-verify's pass/fail contract)."""
    rid = receipt.get("receipt_id", "<unknown>")
    version = receipt.get("signing_version")
    if version != SIGNING_V2_ED25519:
        raise VerificationError(
            f"receipt {rid}: signing_version is {version!r}, expected "
            f"{SIGNING_V2_ED25519!r} (legacy receipts verify via the legacy path)"
        )
    sig_hex = receipt.get("signature")
    if not sig_hex:
        raise VerificationError(f"receipt {rid}: missing signature")
    try:
        signature = bytes.fromhex(sig_hex)
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    except (ValueError, TypeError) as exc:
        raise VerificationError(f"receipt {rid}: malformed key or signature: {exc}") from exc
    try:
        pub.verify(signature, canonical_bytes(receipt))
    except InvalidSignature as exc:
        raise VerificationError(
            f"receipt {rid}: signature INVALID — body was altered after signing "
            f"or signed by a different key"
        ) from exc
    return True


def _cli() -> int:
    parser = argparse.ArgumentParser(prog="signers", description="TRS-2 key tooling")
    sub = parser.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    gen.add_argument("--out-prefix", default="titan", help="writes <prefix>.key / <prefix>.pub")
    args = parser.parse_args()
    if args.cmd == "keygen":
        priv_hex, pub_hex = generate_keypair()
        priv_path, pub_path = f"{args.out_prefix}.key", f"{args.out_prefix}.pub"
        with open(priv_path, "w", encoding="ascii") as f:
            f.write(priv_hex + "\n")
        os.chmod(priv_path, 0o600)
        with open(pub_path, "w", encoding="ascii") as f:
            f.write(pub_hex + "\n")
        print(f"private key -> {priv_path} (mode 0600) — customer trust domain ONLY")
        print(f"public  key -> {pub_path}  — distribute to verifiers/auditors")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
