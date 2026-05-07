import json
import pytest
import jwt
from axg.models import DecisionRequest, Decision
from axg.engine import DecisionEngine
from axg.crypto import key_manager, hash_payload

@pytest.mark.asyncio
async def test_passport_cryptographic_validation_e2e():
    """
    Rigor 10/10 Proof: AXG generates a Passport (JWT) and we validate it 
    cryptographically using the public key, checking issuer, audience, and payload hash.
    """
    engine = DecisionEngine()
    
    # 1. Simulate a request with a specific payload
    payload = {"amount": 100, "merchant": "Apple Store"}
    request = DecisionRequest(
        execution_id="exec_rigor_10_10",
        tenant_id="enterprise_client",
        app_id="muai_console",
        plugin_id="finnorte",
        source="test_runner",
        action_type="create_expense",
        payload=payload,
        llm={"confidence": 0.95}
    )
    
    # 2. Process decision to get the Passport (AWAITED)
    response = await engine.decide(request)
    passport_jwt = response.passport
    
    assert passport_jwt is not None
    print(f"\n[PASSPORT E2E] Generated JWT: {passport_jwt[:20]}...")

    # 3. REAL CRYPTOGRAPHIC VALIDATION (SDK Logic)
    try:
        decoded = jwt.decode(
            passport_jwt,
            key_manager.public_key,
            algorithms=["RS256"],
            audience="muai_console",
            issuer="axg-engine"
        )
        
        # 4. Validate Claims
        assert decoded["sub"] == "exec_rigor_10_10"
        assert decoded["decision"] == Decision.ALLOW.value
        assert decoded["action_type"] == "create_expense"
        
        # 5. Integrity Check (Payload Hash)
        local_hash = hash_payload(response.actionable_payload)
        assert decoded["payload_hash"] == local_hash
        
        print("[PASSPORT E2E] Cryptographic signature VERIFIED.")
        print("[PASSPORT E2E] Audience and Issuer VERIFIED.")
        print("[PASSPORT E2E] Payload Integrity (Hash) VERIFIED.")
        
    except Exception as e:
        pytest.fail(f"Cryptographic validation failed: {e}")

if __name__ == "__main__":
    # For direct execution
    import asyncio
    asyncio.run(test_passport_cryptographic_validation_e2e())
