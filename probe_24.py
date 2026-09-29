"""24-probe adversarial capability audit vs BRD v2.0 / FRD v1.0 / TDD v1.0.
Falsification style: capability probes ATTACK and pass when caught;
gap probes assert NOT-BUILT so absence is recorded, not implied.
Verdicts: PROVEN (attack caught live) / NOT-BUILT (asserted absent) /
LIMITATION (honest permanent negative). Run: python probe_24.py
"""
import hashlib, json, os, re, sys, time, subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from titan_gate.canonical import canonical_bytes_jcs, JCSError
from titan_gate.trs2 import build_trs2_event, TRS2SchemaError
from titan_gate.trs2_writer import (build_trs2_receipt, verify_trs2_receipt,
                                    TRS2ReceiptError)
from titan_gate.chain_state import latest_receipt_hash, ChainStateError
from titan_gate.rekor_inclusion import (verify_inclusion_proof,
                                        verify_checkpoint_signature,
                                        RekorVerificationError)

R = []
def probe(n, ref, name, fn):
    try:
        verdict, note = fn()
    except Exception as e:
        verdict, note = "ERROR", f"{type(e).__name__}: {e}"
    R.append((n, ref, name, verdict, note))
    print(f"  P{n:02d} [{verdict:9s}] {ref:14s} {name}" + (f" — {note}" if note else ""))

PRIV = Ed25519PrivateKey.generate(); PUB = PRIV.public_key()
ATTACKER = Ed25519PrivateKey.generate()
def sig(d): return PRIV.sign(d)
def ev(n=1):
    return build_trs2_event(source_id="s", source_event_id=f"e{n}",
        event_time="2026-08-07T09:00:00Z", ingest_time="2026-08-07T09:00:30Z",
        agent_ref="a1", principal_ref="u:p",
        action=dict(category="data_access", operation="read",
                    target_hash="a"*64, attributes_hash="b"*64),
        outcome=dict(value="success"))
def chain(k):
    prev, out = "GENESIS", []
    for i in range(k):
        r = build_trs2_receipt(event=ev(i), tenant_id="t", seq=i,
                               prev_receipt_hash=prev, sign_fn=sig, key_id="k")
        out.append(r); prev = r["receipt_hash"]
    return out
def caught(fn, exc):
    try: fn(); return False
    except exc: return True
def src(path): return open(path, encoding="utf-8").read()

print("\n=== GROUP A: cryptographic core (moat #4) ===")
probe(1, "KEY-01/AT-11", "Forged receipt (attacker key) rejected", lambda:
    ("PROVEN","") if caught(lambda: verify_trs2_receipt(
        build_trs2_receipt(event=ev(), tenant_id="t", seq=0,
            prev_receipt_hash="GENESIS",
            sign_fn=lambda d: ATTACKER.sign(d), key_id="k"), PUB),
        TRS2ReceiptError) else ("FAIL","forgery verified!"))
probe(2, "RCP-01/AT-15", "Single-byte body tamper detected", lambda: (lambda r:
    ("PROVEN","") if (r[1]["event"].update(agent_ref="a2") or
    caught(lambda: verify_trs2_receipt(r[1], PUB), TRS2ReceiptError))
    else ("FAIL",""))(chain(3)))
def _p3():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        rs = chain(4); del rs[2]
        for i,r in enumerate(rs): open(f"{d}/r{i:03d}.json","w").write(json.dumps(r))
        return ("PROVEN","") if caught(lambda: latest_receipt_hash(d), ChainStateError) else ("FAIL","deletion undetected")
probe(3, "FR-VER-1/AT-18", "Receipt deletion detected (tree walk)", _p3)
def _p4():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        rs = chain(4); rs[1], rs[2] = rs[2], rs[1]
        for i,r in enumerate(rs): open(f"{d}/r{i:03d}.json","w").write(json.dumps(r))
        # tree walk is order-independent; reorder detection is --chain's job:
        from titan_gate.verify import _verify_chain
        rc = subprocess.run([sys.executable,"-c","pass"])  # placeholder no-op
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = _verify_chain(d, None, None, "json", False)
        out = json.loads(buf.getvalue())
        return ("PROVEN",out["err_code"] or "") if code != 0 else ("FAIL","reorder passed")
probe(4, "FR-VER-1", "Reorder detected in claimed-order walk", _p4)
probe(5, "trs2_writer", "Mid-chain GENESIS splice rejected per-receipt", lambda:
    ("PROVEN","") if caught(lambda: build_trs2_receipt(event=ev(), tenant_id="t",
        seq=5, prev_receipt_hash="GENESIS", sign_fn=sig, key_id="k"),
        TRS2ReceiptError) else ("FAIL",""))
def _p6():
    import tempfile, io, contextlib
    from titan_gate.verify import _verify_chain
    with tempfile.TemporaryDirectory() as d:
        rs = chain(3); rs[2]["schema_version"] = "receipt_v1"
        for i,r in enumerate(rs): open(f"{d}/r{i:03d}.json","w").write(json.dumps(r))
        pk = f"{d}/pub.hex"; open(pk,"w").write(PUB.public_bytes_raw().hex())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = _verify_chain(d, None, pk, "json", False)
        out = json.loads(buf.getvalue())
        return ("PROVEN",out["err_code"]) if out.get("err_code")=="ERR_CHAIN_PROFILE_MISMATCH" else ("FAIL",str(out))
probe(6, "SPEC-2 §1.3", "Canonicalization-steering (profile flip) named", _p6)
probe(7, "TDD §2.4", "6962 node-as-leaf second-preimage rejected", lambda:
    ("PROVEN","") if caught(lambda: verify_inclusion_proof(
        leaf_data=b"\x01"+b"x"*64, leaf_index=0, tree_size=2,
        proof_hashes=[b"\x00"*32], expected_root=hashlib.sha256(b"y").digest()),
        RekorVerificationError) else ("FAIL",""))
probe(8, "SPEC-2 §3.2", "JCS UTF-16 key order (non-BMP) correct", lambda:
    ("PROVEN","") if canonical_bytes_jcs({"\ue000":1,"\U0001d11e":2}).index(
        "\U0001d11e".encode()) < canonical_bytes_jcs(
        {"\ue000":1,"\U0001d11e":2}).index("\ue000".encode())
    else ("FAIL","codepoint order leaked"))

print("\n=== GROUP B: notary properties (the thesis, executable) ===")
probe(9, "RCP-03/AT-17", "Payload smuggling (any name, any level) rejected", lambda:
    ("PROVEN","") if all(caught(lambda kk=k: build_trs2_event(**{**dict(
        source_id="s",source_event_id="e",event_time="t",ingest_time="t",
        agent_ref="a",principal_ref="p",
        action=dict(category="c",operation="o",target_hash="a"*64,
                    attributes_hash="b"*64),outcome=dict(value="v")), kk:"DATA"}),
        TRS2SchemaError) for k in ("payload","content","prompt","response"))
    else ("FAIL",""))
probe(10, "KEY-03/NG-04", "Vendor cannot originate outcomes (constant true)", lambda:
    ("PROVEN","") if caught(lambda: build_trs2_event(source_id="s",
        source_event_id="e",event_time="t",ingest_time="t",agent_ref="a",
        principal_ref="p",action=dict(category="c",operation="o",
        target_hash="a"*64,attributes_hash="b"*64),
        outcome=dict(value="v",recorded_by_source=False)), TRS2SchemaError)
    else ("FAIL","vendor-originated outcome accepted"))
def _p11():
    r = chain(1)[0]
    r["event"]["extra_field"] = "smuggled"
    body = {k:v for k,v in r.items() if k not in ("sig","receipt_hash")}
    r["receipt_hash"] = hashlib.sha256(canonical_bytes_jcs(body)).hexdigest()
    r["sig"]["value"] = PRIV.sign(bytes.fromhex(r["receipt_hash"])).hex()
    return ("PROVEN","") if caught(lambda: verify_trs2_receipt(r, PUB),
        TRS2ReceiptError) else ("FAIL","validly-SIGNED schema violation passed")
probe(11, "FR-VER-1", "Correctly-signed schema violation still FAILS", _p11)
probe(12, "SPEC-2 §2.5", "Non-canonical digest forms rejected", lambda:
    ("PROVEN","") if all(caught(lambda h=h: build_trs2_event(source_id="s",
        source_event_id="e",event_time="t",ingest_time="t",agent_ref="a",
        principal_ref="p",action=dict(category="c",operation="o",
        target_hash=h,attributes_hash="b"*64),outcome=dict(value="v")),
        TRS2SchemaError) for h in ("A"*64, "a"*64+"\n", "a"*63))
    else ("FAIL",""))

print("\n=== GROUP C: Rule 1 — trust domain (KEY-01/FR-KEY-1) ===")
probe(13, "FR-KEY-1", "Core writer source: no signing capability", lambda:
    ("PROVEN","") if not any(t in src("titan_gate/trs2_writer.py")
        for t in ("Ed25519PrivateKey","TITAN_SIGNING_KEY","from api","import api"))
    else ("FAIL","signing symbol in core"))
probe(14, "FR-KEY-1", "Evidence-core package holds no key env access", lambda:
    ("PROVEN","") if not any("TITAN_SIGNING_KEY" in src(f"titan_gate/{f}")
        for f in os.listdir("titan_gate") if f.endswith(".py"))
    else ("FAIL","key env var referenced in titan_gate/"))
probe(15, "G1 legacy", "HMAC verify-implies-forge (TRS-1 legacy only)", lambda:
    ("LIMITATION","hmac-sha256-v1 receipts: auditor key can forge; "
     "golden-pinned legacy, ed25519-v1 is the offered path"))

print("\n=== GROUP D: gaps as recorded facts (Rule 3 boundary) ===")
def absent(path_or_check, note):
    return lambda: ("NOT-BUILT", note)
probe(16, "WO-6/ING-01", "Production ingest emits TRS-2", lambda:
    ("NOT-BUILT","ci_evaluate/api emit TRS-1 only; no agent-event source wired")
    if "trs2" not in src("scripts/ci_evaluate.py").lower() else
    ("CHECK","trs2 referenced in ci_evaluate — verify manually"))
probe(17, "WO-8/RPT-01", "Bundles carry chain (prev preserved)", lambda:
    ("NOT-BUILT","proof_bundle_v1 strips prev_receipt_hash")
    if "prev_receipt_hash" not in src("scripts/generate_proof_bundle.py") else
    ("CHECK","prev referenced in bundle script — verify manually"))
probe(18, "WO-4.2/RCP-02", "Rekor submission client", lambda:
    ("NOT-BUILT","4.1 math PROVEN offline; no submission, no live anchor")
    if not os.path.exists("titan_gate/rekor_client.py") else ("CHECK","exists"))
probe(19, "WO-5/RCP-02", "RFC 3161 / eIDAS timestamp leg", lambda:
    ("NOT-BUILT","second anchor leg absent; eIDAS presumption unclaimed"))
probe(20, "WO-7/KEY-01", "Customer-key separation at runtime", lambda:
    ("NOT-BUILT","api/ signs in-process via env key; sign_fn seam ready")
    if "TITAN_SIGNING_KEY" in src("api/receipt_signing.py") + src("api/signers.py")
    else ("CHECK","env key not found in api — verify manually"))
probe(21, "ING-03/FR-ING-6", "Gap receipts / source health", lambda:
    ("NOT-BUILT","no gap receipt type, no source health machine"))
probe(22, "IDB-01/FR-IDB-1", "Identity resolution (agent registry)", lambda:
    ("NOT-BUILT","agent_ref/principal_ref carried verbatim; no resolver"))
probe(23, "RET-01/FR-EVD-4", "Retention floor / legal hold", lambda:
    ("NOT-BUILT","no retention machinery of any kind"))
def _p24():
    rs = chain(2000)
    t0 = time.perf_counter()
    for r in rs: verify_trs2_receipt(r, PUB)
    dt = time.perf_counter() - t0
    est10k = dt * 5
    return (("PROVEN" if est10k < 5 else "CHECK"),
            f"2k full-verify {dt:.2f}s -> 10k est {est10k:.1f}s (AT bar: <5s)")
probe(24, "WO-2 AT", "10k-chain verify under 5s (TRS-2, extrapolated)", _p24)

print("\n" + "="*70)
c = {}
for _,_,_,v,_ in R: c[v] = c.get(v,0)+1
print("VERDICTS: " + "  ".join(f"{k}:{v}" for k,v in sorted(c.items())))
print("Any FAIL or ERROR above is a claims-discipline incident: investigate before any external conversation.")
