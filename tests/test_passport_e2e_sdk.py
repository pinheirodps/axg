import json
import pytest
from axg.audit import AuditManager
from axg.models import DecisionRequest, Decision, DecisionResponse
from axg.engine import DecisionEngine

def test_passport_generation_and_internal_validation():
    """
    E2E Proof: AXG generates a passport that can be validated.
    This demonstrates the contract between AXG and its consumers (SDKs).
    """
    engine = DecisionEngine()
    
    # 1. Simulate a request
    request = DecisionRequest(
        execution_id="test_e2e_001",
        tenant_id="finnorte",
        app_id="muai",
        plugin_id="finnorte",
        action_type="categorize_transaction",
        payload={"amount": 100},
        llm={"confidence": 0.9}
    )
    
    # 2. Process decision
    response = engine.decide(request)
    
    # 3. Verify passport exists and is signed
    assert response.passport is not None
    assert "signature" in response.passport
    assert response.passport["execution_id"] == "test_e2e_001"
    
    # 4. (SDK Simulation) Validate the passport
    # In a real SDK, this would verify the cryptographic signature.
    # Here we verify the structure matches the SDK expectations.
    passport = response.passport
    required_fields = ["execution_id", "decision", "risk_level", "timestamp", "signature", "public_key"]
    for field in required_fields:
        assert field in passport, f"Missing field {field} in passport"

    print("\n[PASSPORT E2E] Passport generated and validated successfully.")

if __name__ == "__main__":
    test_passport_generation_and_internal_validation()
