import hashlib
import uuid
from datetime import datetime, timezone

from api.constants import (
    ENGINE_VERSION, CONTRACT_VERSION, SCORING_FORMULA_VERSION,
    POLICY_VERSION, MERKLE_ALGORITHM, SIGNING_VERSION,
    SCORE_PASS, SCORE_WARN, VERDICT_PASS, VERDICT_WARN, VERDICT_FAIL,
)
from api.receipt_signing import compute_receipt_hash, compute_signature
from judge_engine.v1 import structural_judge, semantic_judge, policy_judge

STRUCTURAL_WEIGHT = 0.6
SEMANTIC_WEIGHT = 0.4


def evaluate(artifact, scope, tenant_id, repo, repo_full_name,
             pr_number, pr_title, branch, base_branch, commit_sha,
             key_hex, prev_receipt_hash="GENESIS"):
    now = datetime.now(timezone.utc)
    evaluated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    root_date = now.strftime("%Y-%m-%d")
    st = structural_judge.evaluate(artifact, scope)
    se = semantic_judge.evaluate(artifact, scope)
    hv = st["hard_violations"] + se.get("hard_violations", [])
    pv = st["process_violations"] + se.get("process_violations", [])
    po = policy_judge.evaluate(artifact, scope, hv, pv)
    ss = st["structural_score"]
    sems = se["semantic_score"]
    comp = round(STRUCTURAL_WEIGHT * ss + SEMANTIC_WEIGHT * sems, 4)
    verdict = classify(comp, hv)
    ah = hashlib.sha256(artifact.encode("utf-8")).hexdigest()
    sch = hashlib.sha256(str(sorted(scope.items())).encode("utf-8")).hexdigest()
    ph = hashlib.sha256((ah + sch).encode("utf-8")).hexdigest()
    receipt = {
        "schema_version": "receipt_v1",
        "receipt_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "repo": repo,
        "repo_full_name": repo_full_name,
        "pr_number": pr_number,
        "pr_title": pr_title,
        "branch": branch,
        "base_branch": base_branch,
        "commit_sha": commit_sha,
        "evaluated_at": evaluated_at,
        "root_date": root_date,
        "engine_version": ENGINE_VERSION,
        "contract_version": CONTRACT_VERSION,
        "scoring_formula_version": SCORING_FORMULA_VERSION,
        "policy_version": POLICY_VERSION,
        "merkle_algorithm": MERKLE_ALGORITHM,
        "signing_version": SIGNING_VERSION,
        "structural_score": ss,
        "semantic_score": sems,
        "composite_score": comp,
        "verdict": verdict,
        "hard_violations": hv,
        "process_violations": pv,
        "artifact_hash": ah,
        "scope_hash": sch,
        "provenance_hash": ph,
        "prev_receipt_hash": prev_receipt_hash,
        "ai_attributed": False,
        "soc2_controls": po["soc2_controls"],
        "evaluation_manifest": {
            "engine_version": ENGINE_VERSION,
            "contract_version": CONTRACT_VERSION,
            "scoring_formula_version": SCORING_FORMULA_VERSION,
            "policy_version": POLICY_VERSION,
            "merkle_algorithm": MERKLE_ALGORITHM,
            "signing_version": SIGNING_VERSION,
            "evaluated_at": evaluated_at,
        },
    }
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    receipt["signature"] = compute_signature(receipt, key_hex)
    return receipt


def classify(comp, hv):
    if hv:
        return VERDICT_FAIL
    if comp >= SCORE_PASS:
        return VERDICT_PASS
    if comp >= SCORE_WARN:
        return VERDICT_WARN
    return VERDICT_FAIL
