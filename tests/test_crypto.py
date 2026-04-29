from axg.crypto import get_private_key, get_public_key, hash_payload, sign_decision
import jwt

def test_key_generation():
    pub = get_public_key()
    priv = get_private_key()
    assert pub
    assert priv
    assert "BEGIN PUBLIC KEY" in pub
    assert "BEGIN PRIVATE KEY" in priv

def test_hash_payload():
    payload1 = {"amount": 100, "merchant": "Uber"}
    payload2 = {"merchant": "Uber", "amount": 100}
    assert hash_payload(payload1) == hash_payload(payload2)

def test_sign_decision():
    token = sign_decision(
        execution_id="123",
        app_id="test_app",
        decision="ALLOW",
        action_type="add_expense",
        actionable_payload={"amount": 10}
    )
    assert token
    
    # Verify token
    pub_key = get_public_key()
    decoded = jwt.decode(token, pub_key, algorithms=["RS256"], audience="test_app")
    assert decoded["sub"] == "123"
    assert decoded["decision"] == "ALLOW"
    assert decoded["payload_hash"] == hash_payload({"amount": 10})

def test_crypto_env_vars(monkeypatch):
    monkeypatch.setenv("AXG_PRIVATE_KEY", "env_private_key\\n")
    monkeypatch.setenv("AXG_PUBLIC_KEY", "env_public_key\\n")
    
    assert get_private_key() == "env_private_key\n"
    assert get_public_key() == "env_public_key\n"

def test_public_key_from_private_key(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    monkeypatch.setenv("AXG_PRIVATE_KEY", priv_pem.replace("\n", "\\n"))
    monkeypatch.delenv("AXG_PUBLIC_KEY", raising=False)
    
    pub = get_public_key()
    assert pub
    assert "BEGIN PUBLIC KEY" in pub

    token = sign_decision(
        execution_id="private-only",
        app_id="test_app",
        decision="ALLOW",
        action_type="add_expense",
        actionable_payload={"amount": 10},
    )
    decoded = jwt.decode(token, pub, algorithms=["RS256"], audience="test_app")
    assert decoded["sub"] == "private-only"
    assert decoded["payload_hash"] == hash_payload({"amount": 10})


def test_sign_decision_failure(monkeypatch):
    def mock_encode(*args, **kwargs):
        raise Exception("Mock error")
    
    monkeypatch.setattr(jwt, "encode", mock_encode)
    
    import pytest
    with pytest.raises(ValueError, match="Could not generate cryptographic decision token"):
        sign_decision("1", "app", "ALLOW", "act", {})
