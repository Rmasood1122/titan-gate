"""Rekor submission client + anchor record parsing (WO-4.2b).

Trust boundary (Rule 1): this module NEVER signs. The signature over
the artifact hash arrives as an argument, produced upstream through
the sign_fn seam under the TENANT key — so the public Rekor entry is
customer-attributable, never vendor-attributable. Executable lint in
tests forbids signing symbols, key env names, and signing-method
calls in this source.

Dependency policy: stdlib urllib only. The verifier-side inclusion
math lives in rekor_inclusion.py with zero network; this module is
the only place submission happens, and it's writer-side only.

Anchor record: closed schema, checkpoint stored VERBATIM for later
parse_checkpoint_note, and the entry body kept — the log's leaf is
the entry body (canonicalized) hash, NOT the artifact hash, so
without entry_body_b64 offline inclusion verification would have no
leaf to recompute.
"""
import base64
import json
import re
import urllib.error
import urllib.request
from urllib.request import urlopen  # module-level name: mockable in tests

__all__ = [
    "build_hashedrekord_proposal",
    "submit_hashedrekord",
    "parse_entry_to_anchor_record",
    "RekorClientError",
    "ANCHOR_RECORD_FIELDS",
]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

ANCHOR_RECORD_FIELDS = frozenset({
    "anchor_version", "uuid", "log_index", "tree_size", "root_hash",
    "hashes", "checkpoint_raw", "entry_body_b64", "integrated_time",
})


class RekorClientError(ValueError):
    """Proposal construction, submission, or response parsing failed."""


def build_hashedrekord_proposal(*, artifact_hash_hex: str,
                                signature_b64: str,
                                public_key_pem: str) -> dict:
    """Build the documented hashedrekord v0.0.1 proposal. No network,
    no signing — the signature is an input."""
    if not isinstance(artifact_hash_hex, str) or not _HEX64.fullmatch(artifact_hash_hex):
        raise RekorClientError(
            f"artifact_hash_hex must be 64 lowercase hex chars, got "
            f"{artifact_hash_hex!r}")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise RekorClientError("signature_b64 must be a non-empty base64 string")
    try:
        base64.b64decode(signature_b64, validate=True)
    except Exception as e:
        raise RekorClientError(f"signature_b64 is not valid base64: {e}") from e
    if not isinstance(public_key_pem, str) or "BEGIN PUBLIC KEY" not in public_key_pem:
        raise RekorClientError("public_key_pem must be a PEM public key string")
    return {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256",
                              "value": artifact_hash_hex}},
            "signature": {
                "content": signature_b64,
                "publicKey": {"content": base64.b64encode(
                    public_key_pem.encode("utf-8")).decode("ascii")},
            },
        },
    }


def submit_hashedrekord(*, artifact_hash_hex: str, signature_b64: str,
                        public_key_pem: str, base_url: str,
                        timeout: float = 30.0) -> dict:
    """POST the proposal to <base_url>/api/v1/log/entries and return the
    parsed JSON response (the entry map). Raises RekorClientError on
    HTTP or transport failure — the CALLER decides degraded behavior
    (FR-RCP-2 single-leg pattern lands in WO-4.3, not here)."""
    proposal = build_hashedrekord_proposal(
        artifact_hash_hex=artifact_hash_hex, signature_b64=signature_b64,
        public_key_pem=public_key_pem)
    url = base_url.rstrip("/") + "/api/v1/log/entries"
    req = urllib.request.Request(
        url, data=json.dumps(proposal).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Accept": "application/json"},
        method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        raise RekorClientError(
            f"Rekor submission failed: HTTP {e.code} {e.reason} {detail}") from e
    except urllib.error.URLError as e:
        raise RekorClientError(f"Rekor unreachable: {e.reason}") from e
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise RekorClientError(f"Rekor response is not JSON: {e}") from e


def parse_entry_to_anchor_record(entry_response: dict) -> dict:
    """Extract the closed-schema anchor record from a Rekor entry
    response ({uuid: {...}}). Exactly one entry expected."""
    if not isinstance(entry_response, dict) or not entry_response:
        raise RekorClientError("entry response must be a non-empty dict")
    if len(entry_response) != 1:
        raise RekorClientError(
            f"expected exactly one entry in response, got "
            f"{len(entry_response)}")
    uuid, entry = next(iter(entry_response.items()))
    if not isinstance(entry, dict):
        raise RekorClientError("entry value must be a dict")
    try:
        body_b64 = entry["body"]
        integrated_time = entry["integratedTime"]
        proof = entry["verification"]["inclusionProof"]
        record = {
            "anchor_version": "rekor_v1",
            "uuid": uuid,
            "log_index": proof["logIndex"],
            "tree_size": proof["treeSize"],
            "root_hash": proof["rootHash"],
            "hashes": list(proof["hashes"]),
            "checkpoint_raw": proof["checkpoint"],
            "entry_body_b64": body_b64,
            "integrated_time": integrated_time,
        }
    except (KeyError, TypeError) as e:
        raise RekorClientError(
            f"entry response missing required field: {e}") from e
    for f in ("log_index", "tree_size"):
        if not isinstance(record[f], int) or record[f] < 0:
            raise RekorClientError(f"{f} must be a non-negative int")
    if not isinstance(record["root_hash"], str) or not _HEX64.fullmatch(record["root_hash"]):
        raise RekorClientError("rootHash must be 64 lowercase hex chars")
    for i, h in enumerate(record["hashes"]):
        if not isinstance(h, str) or not _HEX64.fullmatch(h):
            raise RekorClientError(f"inclusion hash {i} not 64 lowercase hex")
    assert set(record) == ANCHOR_RECORD_FIELDS
    return record
