"""WO-3 AT-2c: the API does not accept caller-supplied prev_receipt_hash.

A caller who can set prev can fork a chain by construction (FR-ING-5's
rationale applied to our own API). The stateless API produces receipts
marked unchained; only persisting writers with a receipts tree may chain.
"""
from fastapi.testclient import TestClient

from api.main import app, EvaluateRequest

client = TestClient(app)

REQUEST_BODY = {
    "artifact": "# test\n",
    "tenant_id": "wo3-api-test",
    "repo": "titan-gate",
    "repo_full_name": "test/titan-gate",
    "pr_number": 1,
    "pr_title": "t",
    "branch": "b",
    "base_branch": "main",
    "commit_sha": "0" * 40,
}


def test_request_model_has_no_prev_field():
    assert "prev_receipt_hash" not in EvaluateRequest.model_fields, \
        "callers must not assert their own chain position"


def test_caller_supplied_prev_is_ignored(monkeypatch):
    monkeypatch.setenv("TITAN_SIGNING_KEY", "ab" * 32)
    resp = client.post("/evaluate",
                       json={**REQUEST_BODY, "prev_receipt_hash": "ATTACKER"})
    assert resp.status_code == 200
    assert resp.json()["prev_receipt_hash"] != "ATTACKER"


def test_api_receipts_are_marked_unchained(monkeypatch):
    monkeypatch.setenv("TITAN_SIGNING_KEY", "ab" * 32)
    resp = client.post("/evaluate", json=REQUEST_BODY)
    assert resp.status_code == 200
    assert resp.json()["prev_receipt_hash"] == "UNCHAINED", \
        "stateless API output must be explicitly unchained, not fake-GENESIS"
