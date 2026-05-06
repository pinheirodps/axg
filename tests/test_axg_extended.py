import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from axg.audit import FileAuditSink, WebhookAuditSink, AuditManager
from axg.crypto import _int_to_base64url, KeyManager, sign_decision, hash_payload

# --- Audit Tests ---

@pytest.mark.anyio
async def test_file_audit_sink_success(tmp_path):
    audit_file = tmp_path / "audit.log"
    sink = FileAuditSink(str(audit_file))
    log_data = {"event": "test", "tenant_id": "t1"}
    
    await sink.record(log_data)
    
    assert audit_file.exists()
    content = audit_file.read_text()
    entry = json.loads(content)
    assert entry["event"] == "test"
    assert "timestamp" in entry

@pytest.mark.anyio
async def test_file_audit_sink_error():
    sink = FileAuditSink("/invalid/path/to/audit.log")
    with patch("axg.audit.logger.error") as mock_log:
        await sink.record({"event": "test"})
        mock_log.assert_called()

@pytest.mark.anyio
async def test_webhook_audit_sink_success(respx_mock):
    url = "https://audit.example.com/logs"
    respx_mock.post(url).respond(200)
    
    sink = WebhookAuditSink(url, token="secret-token")
    await sink.record({"event": "test"})
    
    assert respx_mock.calls.last.request.headers["Authorization"] == "Bearer secret-token"
    assert json.loads(respx_mock.calls.last.request.content)["event"] == "test"

@pytest.mark.anyio
async def test_webhook_audit_sink_no_token(respx_mock):
    url = "https://audit.example.com/logs"
    respx_mock.post(url).respond(200)
    
    sink = WebhookAuditSink(url)
    await sink.record({"event": "test"})
    
    assert "Authorization" not in respx_mock.calls.last.request.headers

@pytest.mark.anyio
async def test_webhook_audit_sink_error(respx_mock):
    url = "https://audit.example.com/logs"
    respx_mock.post(url).respond(500)
    
    sink = WebhookAuditSink(url)
    with patch("axg.audit.logger.error") as mock_log:
        await sink.record({"event": "test"})
        mock_log.assert_called()

def test_audit_manager_initialization(monkeypatch):
    monkeypatch.setenv("AXG_AUDIT_FILE", "/tmp/audit.log")
    monkeypatch.setenv("AXG_AUDIT_WEBHOOK", "https://webhook.com")
    monkeypatch.setenv("AXG_AUDIT_WEBHOOK_TOKEN", "token123")
    
    manager = AuditManager()
    assert len(manager.sinks) == 2
    assert isinstance(manager.sinks[0], FileAuditSink)
    assert isinstance(manager.sinks[1], WebhookAuditSink)
    assert manager.sinks[1].token == "token123"

@pytest.mark.anyio
async def test_audit_manager_record():
    mock_sink = AsyncMock()
    manager = AuditManager()
    manager.sinks = [mock_sink]
    
    await manager.record_decision({"decision": "ALLOW"})
    mock_sink.record.assert_called_once()

# --- Crypto Tests ---

def test_int_to_base64url_zero():
    assert _int_to_base64url(0) == "AA"

def test_key_manager_load_from_env(monkeypatch):
    # Generate a real key pair to test loading
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    priv_key = rsa.generate_private_key(65537, 2048, default_backend())
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    pub_pem = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    monkeypatch.setenv("AXG_PRIVATE_KEY", priv_pem.replace("\n", "\\n"))
    monkeypatch.setenv("AXG_PUBLIC_KEY", pub_pem.replace("\n", "\\n"))
    
    km = KeyManager()
    assert km.private_key == priv_pem
    assert km.public_key == pub_pem

def test_key_manager_derive_public_key(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    priv_key = rsa.generate_private_key(65537, 2048, default_backend())
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    monkeypatch.setenv("AXG_PRIVATE_KEY", priv_pem)
    monkeypatch.delenv("AXG_PUBLIC_KEY", raising=False)
    
    km = KeyManager()
    assert "BEGIN PUBLIC KEY" in km.public_key

def test_key_manager_jwks_invalid_key_type():
    km = KeyManager()
    # Mock public_key to something that is not RSA
    with patch("axg.crypto.serialization.load_pem_public_key") as mock_load:
        mock_load.return_value = MagicMock() # Not an RSAPublicKey
        with pytest.raises(ValueError, match="Only RSA keys are supported"):
            km.get_jwks()

def test_key_manager_jwks_error():
    km = KeyManager()
    with patch("axg.crypto.serialization.load_pem_public_key", side_effect=Exception("parse error")):
        with pytest.raises(ValueError, match="Could not generate JWKS"):
            km.get_jwks()

def test_sign_decision_error():
    with patch("axg.crypto.jwt.encode", side_effect=Exception("sign error")):
        with pytest.raises(ValueError, match="Could not generate cryptographic decision token"):
            sign_decision("exec1", "app1", "ALLOW", "action", {})

def test_hash_payload_determinism():
    p1 = {"a": 1, "b": 2}
    p2 = {"b": 2, "a": 1}
    assert hash_payload(p1) == hash_payload(p2)

def test_crypto_helpers():
    from axg.crypto import get_private_key, get_public_key, get_jwks
    assert "BEGIN PRIVATE KEY" in get_private_key()
    assert "BEGIN PUBLIC KEY" in get_public_key()
    assert "keys" in get_jwks()
