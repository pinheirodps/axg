import pytest
from axg_python_sdk import hash_payload, AxgClient, AxgVerificationError
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

@pytest.fixture
def rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pub_key = public_key # Keep as object for signing_key mock
    
    return priv_pem, pub_key

def test_hash_payload():
    p1 = {"amount": 100, "merchant": "Uber"}
    p2 = {"merchant": "Uber", "amount": 100}
    assert hash_payload(p1) == hash_payload(p2)
    assert hash_payload(p1) == "3e66ff52a65f3c436352e70d6cf0b4a6391f921706147bd1b06c13eae608795c"

@pytest.mark.asyncio
async def test_verify_passport_success(rsa_keys):
    priv_pem, pub_key = rsa_keys
    app_id = "test-app"
    payload = {"amount": 50}
    p_hash = hash_payload(payload)
    
    token = jwt.encode(
        {
            "iss": "axg-engine",
            "aud": app_id,
            "sub": "exec-1",
            "decision": "ALLOW",
            "action_type": "test_action",
            "payload_hash": p_hash,
            "exp": 9999999999
        },
        priv_pem,
        algorithm="RS256",
        headers={"kid": "axg-key-001"}
    )

    client = AxgClient("https://axg.local")
    # Pass the public key directly as _signing_key to bypass JWKS fetch in unit test
    claims = await client.verify_passport(token, payload, app_id, _signing_key=pub_key)
    
    assert claims["sub"] == "exec-1"
    assert claims["decision"] == "ALLOW"

@pytest.mark.asyncio
async def test_verify_passport_tampered(rsa_keys):
    priv_pem, pub_key = rsa_keys
    app_id = "test-app"
    
    token = jwt.encode(
        {
            "iss": "axg-engine",
            "aud": app_id,
            "decision": "ALLOW",
            "payload_hash": hash_payload({"amount": 50}),
            "exp": 9999999999
        },
        priv_pem,
        algorithm="RS256",
        headers={"kid": "axg-key-001"}
    )
    
    client = AxgClient("https://axg.local")
    with pytest.raises(AxgVerificationError, match="Payload hash mismatch"):
        await client.verify_passport(token, {"amount": 500}, app_id, _signing_key=pub_key)

@pytest.mark.asyncio
async def test_verify_passport_invalid_decision(rsa_keys):
    priv_pem, pub_key = rsa_keys
    app_id = "test-app"
    
    token = jwt.encode(
        {
            "iss": "axg-engine",
            "aud": app_id,
            "decision": "BLOCK",
            "payload_hash": hash_payload({}),
            "exp": 9999999999
        },
        priv_pem,
        algorithm="RS256"
    )
    
    client = AxgClient("https://axg.local")
    with pytest.raises(AxgVerificationError, match="Action not allowed"):
        await client.verify_passport(token, {}, app_id, _signing_key=pub_key)

@pytest.mark.asyncio
async def test_verify_passport_generic_jwt_error(rsa_keys):
    _, pub_key = rsa_keys
    client = AxgClient("https://axg.local")
    with pytest.raises(AxgVerificationError, match="JWT Verification failed"):
        # Pass invalid token
        await client.verify_passport("invalid-token", {}, "app", _signing_key=pub_key)
