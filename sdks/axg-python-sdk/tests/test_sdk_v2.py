import json
import time
from pathlib import Path

import jwt
import pytest
from axg_python_sdk import (
    AxgVerificationError,
    InMemoryReplayCache,
    _legacy_hash_payload,
    hash_payload,
    verify_passport,
)
from axg_python_sdk.canonical import canonical_json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "canonical_vectors.json").read_text(encoding="utf-8")
)
PAYLOAD = {"category": "Alimentação", "amount": 1500.0, "merchant": "Padaria São João"}


@pytest.fixture(scope="module")
def keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return pem, public


def passport(pem, **claims):
    now = int(time.time())
    base = {
        "iss": "axg-engine", "sub": "exec_1", "aud": "finnorte", "iat": now, "nbf": now, "exp": now + 300,
        "decision": "ALLOW", "action_type": "create_expense", "tenant_id": "tenant_a",
    }
    base.update(claims)
    return jwt.encode(base, pem, algorithm="RS256")


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_shared_canonical_vectors(vector):
    value = json.loads(vector["input"])
    assert canonical_json(value) == vector["canonical"]
    assert hash_payload(value) == vector["sha256"]


def test_v2_passport_with_accents_and_floats_verifies(keys):
    pem, public = keys
    token = passport(pem, ver=2, jti="j1", payload_hash=hash_payload(PAYLOAD))
    claims = verify_passport(token, PAYLOAD, "finnorte", tenant_id="tenant_a", public_key=public)
    assert claims["ver"] == 2


def test_v1_passport_still_verifies_with_legacy_hash(keys):
    pem, public = keys
    token = passport(pem, payload_hash=_legacy_hash_payload(PAYLOAD))
    assert verify_passport(token, PAYLOAD, "finnorte", public_key=public)["payload_hash"]


def test_v2_passport_rejects_tampered_payload(keys):
    pem, public = keys
    token = passport(pem, ver=2, jti="j2", payload_hash=hash_payload(PAYLOAD))
    with pytest.raises(AxgVerificationError) as exc:
        verify_passport(token, {**PAYLOAD, "amount": 15000}, "finnorte", public_key=public)
    assert exc.value.code == "PAYLOAD_TAMPERED"


def test_tenant_mismatch_is_rejected(keys):
    pem, public = keys
    token = passport(pem, ver=2, jti="j3", payload_hash=hash_payload(PAYLOAD))
    with pytest.raises(AxgVerificationError) as exc:
        verify_passport(token, PAYLOAD, "finnorte", tenant_id="tenant_b", public_key=public)
    assert exc.value.code == "TENANT_ID_MISMATCH"


def test_replay_cache_rejects_second_use(keys):
    pem, public = keys
    cache = InMemoryReplayCache()
    token = passport(pem, ver=2, jti="j4", payload_hash=hash_payload(PAYLOAD))

    verify_passport(token, PAYLOAD, "finnorte", public_key=public, replay_cache=cache)
    with pytest.raises(AxgVerificationError) as exc:
        verify_passport(token, PAYLOAD, "finnorte", public_key=public, replay_cache=cache)
    assert exc.value.code == "PASSPORT_REPLAYED"


def test_replay_cache_needs_jti(keys):
    pem, public = keys
    token = passport(pem, payload_hash=_legacy_hash_payload(PAYLOAD))
    with pytest.raises(AxgVerificationError) as exc:
        verify_passport(token, PAYLOAD, "finnorte", public_key=public, replay_cache=InMemoryReplayCache())
    assert exc.value.code == "MISSING_JTI"


def test_replay_cache_forgets_expired_entries():
    cache = InMemoryReplayCache()
    assert cache.check_and_store("old", int(time.time()) - 1)
    assert cache.check_and_store("old", int(time.time()) + 60)  # expired entry was purged
    assert not cache.check_and_store("old", int(time.time()) + 60)


def test_not_yet_valid_passport_is_rejected(keys):
    pem, public = keys
    token = passport(pem, ver=2, jti="j5", nbf=int(time.time()) + 3600, payload_hash=hash_payload(PAYLOAD))
    with pytest.raises(AxgVerificationError) as exc:
        verify_passport(token, PAYLOAD, "finnorte", public_key=public)
    assert exc.value.code == "JWT_ERROR"


def test_canonical_rejects_invalid_values():
    assert canonical_json([False]) == "[false]"
    with pytest.raises(ValueError):
        canonical_json(float("nan"))
    with pytest.raises(TypeError):
        canonical_json(object())


def test_missing_key_material_is_reported(keys):
    pem, _ = keys
    token = passport(pem, ver=2, jti="j6", payload_hash=hash_payload(PAYLOAD))
    with pytest.raises(AxgVerificationError) as exc:
        verify_passport(token, PAYLOAD, "finnorte")
    assert exc.value.code == "VERIFICATION_FAILED"


def test_verification_via_jwks(keys, monkeypatch):
    from unittest.mock import MagicMock

    import axg_python_sdk

    pem, public = keys
    signing_key = MagicMock(key=public)
    jwks_client = MagicMock()
    jwks_client.get_signing_key_from_jwt.return_value = signing_key
    monkeypatch.setattr(axg_python_sdk, "PyJWKClient", MagicMock(return_value=jwks_client))

    token = passport(pem, ver=2, jti="j7", payload_hash=hash_payload(PAYLOAD))
    claims = verify_passport(token, PAYLOAD, "finnorte", jwks_url="https://axg.example/.well-known/jwks.json")
    assert claims["jti"] == "j7"
    axg_python_sdk.PyJWKClient.assert_called_once_with("https://axg.example/.well-known/jwks.json")


@pytest.mark.asyncio
async def test_client_verifies_with_replay_cache(keys):
    from axg_python_sdk import AxgClient

    pem, public = keys
    client = AxgClient("https://axg.example")
    assert client.jwks_url == "https://axg.example/.well-known/jwks.json"
    token = passport(pem, ver=2, jti="j8", payload_hash=hash_payload(PAYLOAD))
    cache = InMemoryReplayCache()
    await client.verify_passport(token, PAYLOAD, "finnorte", public_key=public, replay_cache=cache)
    with pytest.raises(AxgVerificationError):
        await client.verify_passport(token, PAYLOAD, "finnorte", public_key=public, replay_cache=cache)


def test_action_type_allowlist(keys):
    pem, public = keys
    token = passport(pem, ver=2, jti="j9", payload_hash=hash_payload(PAYLOAD))
    with pytest.raises(AxgVerificationError) as exc:
        verify_passport(token, PAYLOAD, "finnorte", allowed_action_types=["create_income"], public_key=public)
    assert exc.value.code == "ACTION_TYPE_MISMATCH"
