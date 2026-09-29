import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TITAN_SIGNING_KEY"] = "0" * 64

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

GOOD_ARTIFACT = (
    "import hashlib\n\n"
    "def compute_hash(data: str) -> str:\n"
    "    try:\n"
    "        return hashlib.sha256(data.encode()).hexdigest()\n"
    "    except Exception as e:\n"
    "        raise ValueError(str(e))\n"
)

BASE_REQUEST = {
    "artifact": GOOD_ARTIFACT,
    "tenant_id": "tenant_test",
    "repo": "test-repo",
    "repo_full_name": "tenant/test-repo",
    "pr_number": 1,
    "pr_title": "Test PR",
    "branch": "feature/test",
    "base_branch": "main",
    "commit_sha": "a" * 40,
    "scope": {"language": "python"},
    "prev_receipt_hash": "GENESIS",
}


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

class TestHealthEndpoint(unittest.TestCase):
    def test_health_returns_200(self):
        r = client.get("/health")
        self.assertEqual(r.status_code, 200)

    def test_health_status_ok(self):
        r = client.get("/health")
        self.assertEqual(r.json()["status"], "ok")

    def test_health_engine_version(self):
        r = client.get("/health")
        self.assertEqual(r.json()["engine_version"], "1.0.0")

    def test_health_contract_version(self):
        r = client.get("/health")
        self.assertEqual(r.json()["contract_version"], "1.0.0")

    def test_health_response_is_json(self):
        r = client.get("/health")
        self.assertIsInstance(r.json(), dict)

    def test_health_has_status_key(self):
        r = client.get("/health")
        self.assertIn("status", r.json())

    def test_health_has_engine_version_key(self):
        r = client.get("/health")
        self.assertIn("engine_version", r.json())

    def test_health_content_type_json(self):
        r = client.get("/health")
        self.assertIn("application/json", r.headers["content-type"])


# ---------------------------------------------------------------------------
# Root endpoint
# ---------------------------------------------------------------------------

class TestRootEndpoint(unittest.TestCase):
    def test_root_returns_200(self):
        r = client.get("/")
        self.assertEqual(r.status_code, 200)

    def test_root_has_service(self):
        r = client.get("/")
        self.assertIn("service", r.json())

    def test_root_is_json(self):
        r = client.get("/")
        self.assertIsInstance(r.json(), dict)

    def test_root_service_is_string(self):
        r = client.get("/")
        self.assertIsInstance(r.json()["service"], str)


# ---------------------------------------------------------------------------
# Evaluate endpoint — positive path
# ---------------------------------------------------------------------------

class TestEvaluateEndpoint(unittest.TestCase):
    def test_evaluate_returns_200(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.status_code, 200)

    def test_evaluate_returns_receipt(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        data = r.json()
        self.assertIn("receipt_id", data)
        self.assertIn("receipt_hash", data)
        self.assertIn("signature", data)

    def test_evaluate_verdict_valid(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertIn(r.json()["verdict"], ["PASS", "WARN", "FAIL"])

    def test_evaluate_scores_in_range(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        data = r.json()
        self.assertGreaterEqual(data["composite_score"], 0.0)
        self.assertLessEqual(data["composite_score"], 1.0)

    def test_evaluate_tenant_id_correct(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["tenant_id"], "tenant_test")

    def test_evaluate_schema_version(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["schema_version"], "receipt_v1")

    def test_evaluate_receipt_hash_length(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(len(r.json()["receipt_hash"]), 64)

    def test_evaluate_signature_length(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(len(r.json()["signature"]), 64)

    def test_evaluate_unchained(self):
        # WO-3.3: stateless API output is explicitly unchained, not fake-GENESIS
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["prev_receipt_hash"], "UNCHAINED")

    def test_evaluate_caller_prev_ignored(self):
        # WO-3.3: a caller who can set prev can fork a chain; the field is dead.
        # Chained writing is covered by tests/test_wo3_writer_chains.py.
        r1 = client.post("/evaluate", json=BASE_REQUEST).json()
        req2 = dict(BASE_REQUEST)
        req2["prev_receipt_hash"] = r1["receipt_hash"]
        req2["pr_number"] = 2
        r2 = client.post("/evaluate", json=req2).json()
        self.assertEqual(r2["prev_receipt_hash"], "UNCHAINED")

    def test_evaluate_repo_preserved(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["repo"], "test-repo")

    def test_evaluate_branch_preserved(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["branch"], "feature/test")

    def test_evaluate_commit_sha_preserved(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["commit_sha"], "a" * 40)

    def test_evaluate_engine_version(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["engine_version"], "1.0.0")

    def test_evaluate_signing_version(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["signing_version"], "hmac-sha256-v1")

    def test_evaluate_merkle_algorithm(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["merkle_algorithm"], "merkle_v1")

    def test_evaluate_hard_violations_is_list(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertIsInstance(r.json()["hard_violations"], list)

    def test_evaluate_process_violations_is_list(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertIsInstance(r.json()["process_violations"], list)

    def test_evaluate_artifact_hash_length(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(len(r.json()["artifact_hash"]), 64)

    def test_evaluate_deterministic_artifact_hash(self):
        r1 = client.post("/evaluate", json=BASE_REQUEST).json()
        r2 = client.post("/evaluate", json=BASE_REQUEST).json()
        self.assertEqual(r1["artifact_hash"], r2["artifact_hash"])


# ---------------------------------------------------------------------------
# Evaluate endpoint — bad inputs
# ---------------------------------------------------------------------------

class TestEvaluateBadInputs(unittest.TestCase):
    def test_missing_tenant_id_returns_422(self):
        bad = dict(BASE_REQUEST)
        del bad["tenant_id"]
        r = client.post("/evaluate", json=bad)
        self.assertEqual(r.status_code, 422)

    def test_missing_field_returns_422(self):
        bad = dict(BASE_REQUEST)
        del bad["artifact"]
        r = client.post("/evaluate", json=bad)
        self.assertEqual(r.status_code, 422)

    def test_missing_repo_returns_422(self):
        bad = dict(BASE_REQUEST)
        del bad["repo"]
        r = client.post("/evaluate", json=bad)
        self.assertEqual(r.status_code, 422)

    def test_missing_commit_sha_returns_422(self):
        bad = dict(BASE_REQUEST)
        del bad["commit_sha"]
        r = client.post("/evaluate", json=bad)
        self.assertEqual(r.status_code, 422)

    def test_empty_body_returns_422(self):
        r = client.post("/evaluate", json={})
        self.assertEqual(r.status_code, 422)

    


# ---------------------------------------------------------------------------
# Evaluate endpoint — different tenants
# ---------------------------------------------------------------------------

class TestEvaluateTenantIsolation(unittest.TestCase):
    def test_different_tenants_different_receipts(self):
        req1 = dict(BASE_REQUEST)
        req2 = dict(BASE_REQUEST)
        req2["tenant_id"] = "other_tenant"
        req2["repo_full_name"] = "other_tenant/repo"
        r1 = client.post("/evaluate", json=req1).json()
        r2 = client.post("/evaluate", json=req2).json()
        self.assertNotEqual(r1["receipt_hash"], r2["receipt_hash"])

    def test_different_tenants_different_signatures(self):
        req1 = dict(BASE_REQUEST)
        req2 = dict(BASE_REQUEST)
        req2["tenant_id"] = "other_tenant"
        req2["repo_full_name"] = "other_tenant/repo"
        r1 = client.post("/evaluate", json=req1).json()
        r2 = client.post("/evaluate", json=req2).json()
        self.assertNotEqual(r1["signature"], r2["signature"])

    def test_tenant_id_in_response(self):
        r = client.post("/evaluate", json=BASE_REQUEST)
        self.assertEqual(r.json()["tenant_id"], BASE_REQUEST["tenant_id"])


if __name__ == "__main__":
    unittest.main()