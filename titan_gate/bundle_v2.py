"""bundle_v2 — the demo kit: a self-contained, chain-carrying evidence
bundle plus its tamper twin. WO-8-core.

Pipeline (every stage is existing [F] machinery; this module is plumbing):
  2 wire-truth Copilot fixture records -> normalize -> ChainAssembler
  (seq, prev_receipt_hash links, Ed25519 signatures, gap open/close via
  silence threshold) -> day-root seal over receipt hashes ->
  anchor_root_v2 with the repo's REAL wire artifacts (live Rekor record
  + real freetsa token) -> bundle dir + surgical tamper twin + manifest
  + README a stranger can follow.

Honest boundary (enforced by AT): events are fixture-derived, the key is
vendor-demo custody. Customer-held keys and live-tenant ingest are
roadmap, stated in the README, never claimed.
"""
import hashlib
import json
import shutil
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.copilot_normalize import normalize_copilot_record
from titan_gate.ingest_assembler import ChainAssembler
from titan_gate.anchor_writer import anchor_root_v2

_FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures"
_COPILOT = _FIXTURES / "copilot"
_ANCHOR_META = (Path(__file__).parent.parent / ".titan-gate" / "anchors" /
                "Rehanrana11" / "Rehanrana11_titan-gate" / "2026-03-06.json")
_TSA_TOKEN = _FIXTURES / "tsa" / "response.tsr"

# Timestamps: 3 actions, silence > 600s (gap opens), recovery (marker
# closes), 3 more actions. 8 receipts total: 6 action + 1 gap + 1 marker.
_POLLS = [
    ("2026-08-06T10:00:00Z", [1]),
    ("2026-08-06T10:05:00Z", [2]),
    ("2026-08-06T10:10:00Z", [1]),
    ("2026-08-06T10:25:00Z", []),      # 15 min silent -> gap opens
    ("2026-08-06T10:40:00Z", [2]),     # recovery -> marker, then action
    ("2026-08-06T10:45:00Z", [1]),
    ("2026-08-06T10:50:00Z", [2]),
]


class BundleV2Error(ValueError):
    """Any bundle generation failure. Fail-closed: partial kits are
    removed rather than left looking complete."""


def _load_record(n: int) -> dict:
    return json.loads((_COPILOT / f"example_{n}_auditdata.json").read_bytes())


def _receipt_files(root: Path):
    return sorted(root.rglob("*.json"))


def generate_demo_bundle(*, out_dir: str) -> dict:
    out = Path(out_dir)
    if not _COPILOT.exists():
        raise BundleV2Error(f"copilot fixtures not found at {_COPILOT}")
    work = out / "_work"
    bundle = out / "bundle"
    twin = out / "bundle_tampered"
    for d in (work, bundle / "receipts", twin):
        d.mkdir(parents=True, exist_ok=True)
    try:
        return _generate(work, bundle, twin)
    except Exception:
        for d in (bundle, twin):
            shutil.rmtree(d, ignore_errors=True)   # no partial kits
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _generate(work: Path, bundle: Path, twin: Path) -> dict:
    # --- 1. fresh demo key (vendor-demo custody, stated in manifest) ---
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw).hex()
    (bundle / "pubkey.hex").write_text(pub_hex, encoding="utf-8")

    # --- 2. build the chain through the real assembler ---
    asm = ChainAssembler(
        receipts_root=work / "receipts", tenant_id="demo-tenant",
        source_id="m365-audit", key_id="demo-k1",
        sign_fn=lambda d: priv.sign(d), silence_threshold_s=600)
    for ts, ns in _POLLS:
        events = [normalize_copilot_record(_load_record(n),
                                           source_id="m365-audit",
                                           ingest_time=ts) for n in ns]
        asm.record_poll(ts, events)

    src_receipts = _receipt_files(work / "receipts")
    if len(src_receipts) < 5:
        raise BundleV2Error(
            f"expected >=5 receipts from demo polls, got {len(src_receipts)}")

    # --- 3. flat-copy receipts into the bundle, seq-ordered names ---
    entries = []
    for rp in src_receipts:
        r = json.loads(rp.read_text(encoding="utf-8"))
        entries.append(r)
    entries.sort(key=lambda r: r["seq"])
    for r in entries:
        name = f"receipt_{r['seq']:05d}.json"
        (bundle / "receipts" / name).write_text(
            json.dumps(r, indent=2, sort_keys=True), encoding="utf-8",
            newline="\n") if False else \
            (bundle / "receipts" / name).write_text(
                json.dumps(r, indent=2, sort_keys=True), encoding="utf-8")

    # --- 4. day root over receipt hashes; anchor with REAL wire legs ---
    root_hex = hashlib.sha256(
        b"".join(bytes.fromhex(r["receipt_hash"]) for r in entries)
    ).hexdigest()
    meta = json.loads(_ANCHOR_META.read_text(encoding="utf-8"))
    rekor_path = (_ANCHOR_META.parent /
                  Path(meta["rekor_record_path"].replace("\\", "/")).name)
    rekor_record = json.loads(rekor_path.read_text(encoding="utf-8"))
    tsa_token = _TSA_TOKEN.read_bytes()
    st = anchor_root_v2(root_hash_hex=root_hex,
                        rekor_fn=lambda _: rekor_record,
                        tsa_fn=lambda _: tsa_token,
                        out_dir=str(work / "anchor"))
    if not st.ok:
        raise BundleV2Error(f"anchoring failed: {st.error}")
    shutil.copy(st.record_path, bundle / "anchor_v2.json")

    # --- 5. manifest + README (honest boundary, AT-enforced) ---
    manifest = {
        "schema": "titan_demo_bundle_v2",
        "source": "fixture-derived",
        "key_custody": "vendor-demo",
        "receipt_count": len(entries),
        "chain_root_sha256": root_hex,
        "anchor_note": ("anchor legs are REAL wire artifacts (live Rekor "
                        "entry + RFC 3161 token) demonstrating the "
                        "verification mechanism; they cover the repo's "
                        "production root, not this demo chain's root — "
                        "stated here so the demo overclaims nothing"),
        "verify_command": ("python -m titan_gate.verify --chain receipts "
                           "--pubkey pubkey.hex"),
    }
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    (bundle / "README-verification.md").write_text(_README, encoding="utf-8")

    # --- 6. surgical tamper twin: one byte in one signed field ---
    shutil.copytree(bundle / "receipts", twin / "receipts",
                    dirs_exist_ok=True)
    for extra in ("pubkey.hex", "anchor_v2.json", "manifest.json",
                  "README-verification.md"):
        shutil.copy(bundle / extra, twin / extra)
    victims = sorted((twin / "receipts").glob("*.json"))
    victim = victims[len(victims) // 2]
    v = json.loads(victim.read_text(encoding="utf-8"))
    h = v["receipt_hash"]
    v["receipt_hash"] = ("0" if h[0] != "0" else "1") + h[1:]
    victim.write_text(json.dumps(v, indent=2, sort_keys=True),
                      encoding="utf-8")
    return {"bundle": str(bundle), "twin": str(twin),
            "receipts": len(entries)}


_README = """# Titan Gate — Demo Evidence Bundle: verify it yourself

This directory is self-contained. You need Python 3.11+, the open
titan-gate verifier, and nothing else — no network, no account, nothing
from us.

## 1. Verify the chain (should PASS)

    python -m titan_gate.verify --chain receipts --pubkey pubkey.hex

This checks every receipt's Ed25519 signature against pubkey.hex and
walks the chain from GENESIS: every receipt's prev_receipt_hash must
equal the hash of its predecessor. Deletion, reordering, or alteration
anywhere breaks the walk WITH POSITION.

## 2. Now watch it catch tampering

The sibling directory `bundle_tampered/` is byte-identical to this one
except ONE field of ONE receipt was changed. Run the same command there:
it FAILS and names the position. That is the product: not that
verification passes, but that lying fails, locatably.

## 3. What the gap receipts are

The chain contains a signed `gap` receipt and its closing `marker`:
during the demo window the source went silent past the threshold, and
the silence itself became signed, chained evidence. Outages are
disclosed, never invisible.

## Honest boundary — what this demo is and is not

- Events are FIXTURE-derived (real Microsoft 365 audit-record schema,
  captured examples) — not a live tenant. Live-tenant ingest requires a
  design partner and is roadmap.
- The signing key is vendor-demo custody. In the product architecture,
  customer-held keys mean we cannot fabricate receipts even in
  principle; that component (WO-7) is roadmap, not present here.
- anchor_v2.json shows the dual-anchor record mechanism with REAL wire
  artifacts (a live Rekor inclusion proof and an RFC 3161 token); those
  artifacts cover our repository's production root as a mechanism
  demonstration — see manifest.json `anchor_note`.

Every claim above is enforced by an automated test in the public repo.
"""
