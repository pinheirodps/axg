import pytest
import jwt
from axg.api import app
from axg.crypto import get_public_key, key_manager
from fastapi.testclient import TestClient

def test_passport_signature_verification():
    client = TestClient(app)
    
    # 1. Request a decision
    payload = {
        "execution_id": "exec_verify_001",
        "tenant_id": "tenant_001",
        "app_id": "finnorte",
        "plugin_id": "finnorte",
        "source": "api",
        "action_type": "create_expense",
        "payload": {
            "merchant": "Uber",
            "amount": 10,
            "currency": "EUR"
        },
        "llm": {"confidence": 0.99}
    }
    
    response = client.post("/v1/decisions", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    passport = data.get("passport")
    assert passport is not None, "Decision should have a passport token"
    
    # 2. Get public key from certs endpoint
    certs_resp = client.get("/v1/certs")
    assert certs_resp.status_code == 200
    public_key = certs_resp.json()["public_key"]
    
    # 3. Verify the passport token
    decoded = jwt.decode(
        passport,
        public_key,
        algorithms=["RS256"],
        audience="finnorte",
        issuer="axg-engine"
    )
    
    assert decoded["sub"] == "exec_verify_001"
    assert decoded["decision"] == "ALLOW"
    assert decoded["action_type"] == "create_expense"
    assert "payload_hash" in decoded

def test_jwks_endpoint_discovery():
    client = TestClient(app)
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    jwks = response.json()
    assert "keys" in jwks
    assert jwks["keys"][0]["kid"] == key_manager.KID
    assert jwks["keys"][0]["alg"] == "RS256"
