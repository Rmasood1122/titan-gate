from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import hashlib
import os

from api.constants import ENGINE_VERSION, CONTRACT_VERSION
from judge_engine.v1.engine import evaluate

app = FastAPI(
    title="Titan Gate",
    description="Cryptographic change-control system for AI-assisted software engineering",
    version=ENGINE_VERSION,
)


class EvaluateRequest(BaseModel):
    artifact: str
    tenant_id: str
    repo: str
    repo_full_name: str
    pr_number: int
    pr_title: str
    branch: str
    base_branch: str
    commit_sha: str
    scope: Dict[str, Any] = {}


class EvaluateResponse(BaseModel):
    schema_version: str
    receipt_id: str
    tenant_id: str
    repo: str
    verdict: str
    composite_score: float
    structural_score: float
    semantic_score: float
    receipt_hash: str
    signature: str
    prev_receipt_hash: str
    evaluated_at: str
    hard_violations: List[Dict[str, Any]]
    process_violations: List[Dict[str, Any]]


def get_signing_key():
    key = os.environ.get("TITAN_SIGNING_KEY")
    if not key:
        raise HTTPException(status_code=500, detail="TITAN_SIGNING_KEY not configured")
    return key


@app.get("/health")
def health():
    return {
        "status": "ok",
        "engine_version": ENGINE_VERSION,
        "contract_version": CONTRACT_VERSION,
    }


@app.post("/evaluate")
def evaluate_artifact(request: EvaluateRequest):
    key = get_signing_key()
    receipt = evaluate(
        artifact=request.artifact,
        scope=request.scope,
        tenant_id=request.tenant_id,
        repo=request.repo,
        repo_full_name=request.repo_full_name,
        pr_number=request.pr_number,
        pr_title=request.pr_title,
        branch=request.branch,
        base_branch=request.base_branch,
        commit_sha=request.commit_sha,
        key_hex=key,
        prev_receipt_hash="UNCHAINED",
    )
    return receipt


@app.get("/")
def root():
    return {
        "service": "Titan Gate",
        "engine_version": ENGINE_VERSION,
        "contract_version": CONTRACT_VERSION,
        "docs": "/docs",
    }
