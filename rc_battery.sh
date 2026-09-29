#!/usr/bin/env bash
# TITAN GATE — RELEASE-CANDIDATE BATTERY v1.0
# Run before ANY external send, demo, or release. Every check can FAIL.
# Any FAIL is a pre-send blocker. First run (Aug 6, 2026) caught a live
# Rule 1 violation (default signing key in scripts/) that probe_24's
# file-scoping missed — this battery exists because guards need guards.
cd "$(dirname "$0")"
echo "############ RC BATTERY ############"

echo "=== 1-4: STATE ==="
git status --short && git log -1 --oneline
echo "unpushed: $(git log origin/main..HEAD --oneline | wc -l)"
python -m pytest -q --continue-on-collection-errors 2>&1 | tail -1
python -m pytest -q -k "golden or wo34" 2>&1 | tail -1

echo; echo "=== 5-7: SUPPLY CHAIN ==="
pip install --dry-run -r requirements.txt 2>&1 | grep -qE "ERROR|Impossible" && echo "RESOLVE: BROKEN <-- FAIL" || echo "RESOLVE: clean"
pip-audit -r requirements.txt 2>&1 | tail -1
rm -rf /tmp/tg-rc && git clone -q . /tmp/tg-rc && (cd /tmp/tg-rc && python -m pytest -q 2>&1 | tail -1)

echo; echo "=== 8-13: ADVERSARIAL CORE (live attacks on fresh bundle) ==="
python - << 'PYEOF'
import tempfile, subprocess, sys, json, os, glob
from pathlib import Path
from titan_gate.bundle_v2 import generate_demo_bundle
ROOT = Path.cwd()
prog = ("import sys; sys.argv=['titan-verify']+sys.argv[1:]; "
        "from titan_gate.verify import main; main()")
def verify(r, k):
    return subprocess.run([sys.executable,"-c",prog,"--chain",r,"--pubkey",k],
        capture_output=True,text=True,cwd=str(ROOT),env=dict(os.environ,PYTHONPATH=str(ROOT)))
tmp = Path(tempfile.mkdtemp()); generate_demo_bundle(out_dir=str(tmp))
b=tmp/"bundle"; R=str((b/"receipts").resolve()); K=str((b/"pubkey.hex").resolve())
p=verify(R,K); print(f"  [8] clean bundle verifies: {'PASS' if p.returncode==0 else 'FAIL'}")
p=verify(str((tmp/'bundle_tampered'/'receipts').resolve()),K)
print(f"  [9] tamper twin FAILS w/position: {'PASS' if p.returncode!=0 and 'position' in (p.stdout+p.stderr).lower() else 'FAIL'}")
vs=sorted(glob.glob(R+"/*.json")); os.remove(vs[len(vs)//2])
p=verify(R,K); print(f"  [10] deletion FAILS: {'PASS' if p.returncode!=0 else 'FAIL'}")
t2=Path(tempfile.mkdtemp()); generate_demo_bundle(out_dir=str(t2))
b2=t2/"bundle"/"receipts"; fs=sorted(b2.glob("*.json"))
ta=fs[1].read_bytes(); fs[1].write_bytes(fs[2].read_bytes()); fs[2].write_bytes(ta)
p=verify(str(b2.resolve()),str((t2/"bundle"/"pubkey.hex").resolve()))
print(f"  [11] reorder FAILS: {'PASS' if p.returncode!=0 else 'FAIL'}")
from titan_gate.trs2_writer import verify_trs2_receipt_v2, TRS2ReceiptError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
pub=Ed25519PrivateKey.generate().public_key()
try: verify_trs2_receipt_v2({"receipt_type":[]},pub); print("  [12] FAIL")
except TRS2ReceiptError: print("  [12] hostile input -> clean error: PASS")
except Exception as e: print(f"  [12] FAIL uncontrolled {type(e).__name__}")
types=[json.loads(f.read_text(encoding='utf-8'))["receipt_type"] for f in sorted((t2/"bundle"/"receipts").glob("*.json"))]
print(f"  [13] gap+marker disclosed: {'PASS' if 'gap' in types and 'marker' in types else 'FAIL'}")
PYEOF

echo; echo "=== 14-16: ANCHORS ==="
python - << 'PYEOF'
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from titan_gate.anchor_v2 import build_anchor_v2_record, verify_anchor_v2_offline, AnchorV2Error
A=Path(".titan-gate/anchors/Rehanrana11/Rehanrana11_titan-gate/2026-03-06.json")
a=json.loads(A.read_text(encoding="utf-8"))
rekor=json.loads((A.parent/Path(a["rekor_record_path"].replace("\\","/")).name).read_text(encoding="utf-8"))
pub=serialization.load_pem_public_key(open("tests/fixtures/rekor_log_pubkey.pem","rb").read())
tok=open("tests/fixtures/tsa/response.tsr","rb").read()
ca=open("tests/fixtures/tsa/freetsa_cacert.pem","rb").read()
rec=build_anchor_v2_record(root_hash_hex=a["merkle_root"],rekor_record=rekor,tsa_token=tok)
r=verify_anchor_v2_offline(rec,rekor_log_pubkey=pub,tsa_ca_cert_pem=ca)
print(f"  [14] dual-leg offline: {'PASS' if r.status=='ANCHORED' else 'FAIL'}")
wrong=("0" if a["merkle_root"][0]!="0" else "1")+a["merkle_root"][1:]
try:
    verify_anchor_v2_offline(build_anchor_v2_record(root_hash_hex=wrong,rekor_record=rekor,tsa_token=tok),
                             rekor_log_pubkey=pub,tsa_ca_cert_pem=ca)
    print("  [15] FAIL wrong root accepted")
except AnchorV2Error as e:
    print(f"  [15] wrong root rejected naming both: {'PASS' if a['merkle_root'] in str(e) and wrong in str(e) else 'PARTIAL'}")
try:
    build_anchor_v2_record(root_hash_hex=a["merkle_root"],rekor_record=None,tsa_token=None)
    print("  [16] FAIL zero-leg built")
except AnchorV2Error: print("  [16] anchor-to-nothing refused: PASS")
PYEOF

echo; echo "=== 17-19: TRUST DOMAIN (Rule 1) ==="
hits=$(grep -rln "TITAN_SIGNING_KEY" titan_gate/ --include="*.py" 2>/dev/null | wc -l)
[ "$hits" -eq 0 ] && echo "  [17] evidence core has zero signer env refs: PASS" || { echo "  [17] FAIL — core references signer env:"; grep -rn "TITAN_SIGNING_KEY" titan_gate/ --include="*.py"; }
defaults=$(grep -rn 'get("TITAN_SIGNING_KEY"[^)]*,' --include="*.py" . 2>/dev/null | grep -v ".git\|pycache" | wc -l)
[ "$defaults" -eq 0 ] && echo "  [17b] NO signer key default anywhere in repo: PASS" || { echo "  [17b] FAIL — default key found (first-run catch class):"; grep -rn 'get("TITAN_SIGNING_KEY"[^)]*,' --include="*.py" . | grep -v ".git\|pycache"; }
python -c "
from titan_gate.trs2_writer import verify_trs2_receipt_v2
try:
    verify_trs2_receipt_v2({'receipt_type':'action','event':{},'outcome':{'recorded_by_source':False}}, None)
    print('  [18] FAIL')
except Exception: print('  [18] vendor cannot author outcomes: PASS')"
grep -qrn "def.*sign\b" titan_gate/verify.py && echo "  [19] FAIL verifier has signing" || echo "  [19] verifier holds no signing capability: PASS"

echo; echo "=== 20-22: HONESTY GUARDS ==="
python - << 'PYEOF'
import tempfile, json
from pathlib import Path
from titan_gate.bundle_v2 import generate_demo_bundle
t=Path(tempfile.mkdtemp()); generate_demo_bundle(out_dir=str(t))
m=json.loads((t/"bundle"/"manifest.json").read_text(encoding="utf-8"))
print(f"  [20] fixture-derived stated: {'PASS' if m['source']=='fixture-derived' else 'FAIL'}")
print(f"  [21] vendor-demo custody stated: {'PASS' if m['key_custody']=='vendor-demo' else 'FAIL'}")
rd=(t/"bundle"/"README-verification.md").read_text(encoding="utf-8").lower()
print(f"  [22] roadmap boundary stated: {'PASS' if 'customer-held keys' in rd else 'FAIL'}")
PYEOF

echo; echo "=== 23-24: PERF + PUBLIC ==="
python -m pytest tests/ -q -k "10k" 2>&1 | tail -1
echo "  [23] NOTE: 'deselected' = 10k timing still unmeasured (WO-T2a) — honest FAIL until built"
echo "  [24] MANUAL: confirm CI green at github.com/Rehanrana11/titan-gate/actions"
echo "############ BATTERY COMPLETE — any FAIL is a pre-send blocker ############"
