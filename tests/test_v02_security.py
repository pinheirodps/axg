"""v0.2: caller authentication, Passport v2, canonical hashing, key management, plugin ids."""

import hashlib
import json
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from axg import auth
from axg.api import app
from axg.auth import ANONYMOUS, TRUSTED_LOCAL, AuthConfigError, Caller, authenticate
from axg.canonical import canonical_hash, canonical_json
from axg.crypto import KeyConfigError, KeyManager, hash_payload, key_manager
from axg.engine import DecisionEngine
from axg.models import Decision, DecisionRequest
from axg.plugin_loader import PluginLoader, PluginLoadError
from tests.conftest import TEST_API_KEY, client_config

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "canonical_vectors.json").read_text(encoding="utf-8"))


def decision_request(**overrides) -> DecisionRequest:
    data = {
        "execution_id": "exec_v02",
        "tenant_id": "tenant_a",
        "app_id": "finnorte",
        "plugin_id": "finnorte",
        "agent": {"id": "bot", "type": "service", "permissions": ["expense:create"]},
        "source": "api",
        "action_type": "create_expense",
        "payload": {"merchant": "Padaria", "amount": 12.5, "currency": "EUR", "account_id": "acc_1"},
        "llm": {"confidence": 0.97},
        "intent": {"original": "create_expense", "resolved": "create_expense"},
    }
    data.update(overrides)
    return DecisionRequest(**data)


# ── Canonical JSON (shared vectors with the SDKs) ────────────────────────────

@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_canonical_vectors(vector):
    value = json.loads(vector["input"])
    assert canonical_json(value) == vector["canonical"]
    assert canonical_hash(value) == vector["sha256"]


def test_canonical_tuples_and_invalid_values():
    assert canonical_json((1, "a", False)) == '[1,"a",false]'
    for bad in (float("nan"), float("inf")):
        with pytest.raises(ValueError):
            canonical_json({"x": bad})
    with pytest.raises(TypeError):
        canonical_json({"x": {1, 2}})


def test_hash_payload_is_canonical():
    assert hash_payload({"amount": 1500.0}) == hash_payload({"amount": 1500})


# ── Caller model ─────────────────────────────────────────────────────────────

def test_caller_permission_ceiling():
    scoped = Caller("c", True, frozenset({"finnorte"}), frozenset({"expense:create"}))
    assert scoped.effective_permissions(["expense:create", "admin:all"]) == ["expense:create"]
    assert scoped.may_act_for("finnorte") and not scoped.may_act_for("legal")
    assert TRUSTED_LOCAL.effective_permissions(["x"]) == ["x"]
    assert Caller("c", True, frozenset({"*"}), frozenset({"*"})).effective_permissions(["x"]) == ["x"]


def test_auth_mode_validation(monkeypatch):
    monkeypatch.delenv("AXG_AUTH_MODE", raising=False)
    assert auth.auth_mode() == "required"
    monkeypatch.setenv("AXG_AUTH_MODE", "Optional")
    assert auth.auth_mode() == "optional"
    monkeypatch.setenv("AXG_AUTH_MODE", "off")
    with pytest.raises(AuthConfigError):
        auth.auth_mode()


@pytest.mark.parametrize("raw", ["not json", '{"client_id": "x"}', '[{"client_id": "x"}]', "[1]"])
def test_invalid_client_config(monkeypatch, raw):
    monkeypatch.setenv("AXG_CLIENTS", raw)
    with pytest.raises(AuthConfigError):
        authenticate("any")


def test_authenticate(monkeypatch):
    monkeypatch.delenv("AXG_CLIENTS", raising=False)
    assert authenticate(TEST_API_KEY) is None

    no_ceiling = client_config(client_id="legacy", key_sha256=hashlib.sha256(b"other").hexdigest().upper())
    no_ceiling.pop("permissions")
    monkeypatch.setenv("AXG_CLIENTS", json.dumps([client_config(app_ids=["finnorte"]), no_ceiling]))

    caller = authenticate(TEST_API_KEY)
    assert caller.client_id == "test-client" and caller.authenticated
    assert caller.app_ids == frozenset({"finnorte"})
    # Hash compare is case-insensitive; a client without a ceiling may grant no permission
    legacy = authenticate("other")
    assert legacy.permissions == frozenset()
    assert legacy.effective_permissions(["expense:create"]) == []
    assert authenticate("wrong") is None


@pytest.mark.asyncio
async def test_anonymous_caller_cannot_vouch_for_agent_permissions():
    """In optional mode, claimed permissions must not turn a permission BLOCK into a CONFIRM."""
    from axg.auth import ANONYMOUS
    from axg.engine import DecisionEngine
    from axg.models import Decision, DecisionRequest

    request = DecisionRequest(
        execution_id="anon", tenant_id="t", app_id="finnorte", plugin_id="finnorte", source="api",
        action_type="create_expense", payload={"amount": 10},
        agent={"id": "claims-everything", "permissions": ["expense:create"]}, llm={"confidence": 0.95},
    )
    response = await DecisionEngine().decide(request, ANONYMOUS)
    assert response.decision == Decision.BLOCK
    assert response.passport is None


# ── API: authentication and audience binding ─────────────────────────────────

def _payload():
    return decision_request().model_dump(mode="json")


def test_api_requires_api_key(monkeypatch):
    monkeypatch.delenv("AXG_AUTH_MODE", raising=False)
    response = TestClient(app).post("/v1/decisions", json=_payload())
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("header", ["Bearer wrong-key", "Basic dGVzdA==", "Bearer ", "Bearer"])
def test_api_rejects_invalid_credentials_even_in_optional_mode(monkeypatch, api_client, header):
    monkeypatch.setenv("AXG_AUTH_MODE", "optional")
    response = api_client.post("/v1/decisions", json=_payload(), headers={"Authorization": header})
    assert response.status_code == 401


def test_api_optional_mode_never_allows_anonymous(monkeypatch):
    monkeypatch.setenv("AXG_AUTH_MODE", "optional")
    # An action that needs no permission, so only the missing authentication prevents ALLOW
    read = {**_payload(), "app_id": "claude-code", "plugin_id": "claude-code", "action_type": "Read",
            "payload": {"file_path": "README.md"}}
    body = TestClient(app).post("/v1/decisions", json=read).json()
    assert body["decision"] == "CONFIRM"
    assert body["passport"] is None
    assert "unauthenticated_caller" in body["audit_flags"]


def test_api_authenticated_allow_issues_passport_v2(api_client):
    body = api_client.post("/v1/decisions", json=_payload()).json()
    assert body["decision"] == "ALLOW"

    claims = jwt.decode(body["passport"], key_manager.public_key, algorithms=["RS256"], audience="finnorte")
    assert claims["ver"] == 2
    assert claims["azp"] == "test-client"
    assert claims["tenant_id"] == "tenant_a"
    assert claims["jti"] == body["passport_id"]
    assert claims["policy"].startswith("finnorte@")
    assert claims["payload_hash"] == hash_payload(body["actionable_payload"])
    assert body["actionable_payload"]["account_id"] == "acc_1"  # every field is bound


def test_api_rejects_foreign_audience(monkeypatch):
    monkeypatch.setenv("AXG_CLIENTS", json.dumps([client_config(app_ids=["legal"])]))
    client = TestClient(app, headers={"Authorization": f"Bearer {TEST_API_KEY}"})
    assert client.post("/v1/decisions", json=_payload()).status_code == 403


def _permissioned_plugin(tmp_path) -> PluginLoader:
    plugin_dir = tmp_path / "payments"
    plugin_dir.mkdir()
    (plugin_dir / "rules.json").write_text(json.dumps({
        "plugin": "payments", "version": "1.0.0", "domain": "finance",
        "actions": {"create_expense": {"required_permissions": ["expense:create"], "base_risk": 0.1}},
        "rules": [],
    }), encoding="utf-8")
    return PluginLoader(plugins_dir=tmp_path)


@pytest.mark.asyncio
async def test_agent_permissions_are_capped_by_caller(tmp_path):
    engine = DecisionEngine(loader=_permissioned_plugin(tmp_path))
    request = decision_request(plugin_id="payments", intent={"original": "create_expense"})

    reader = Caller("reader", True, frozenset({"*"}), frozenset({"report:read"}))
    writer = Caller("writer", True, frozenset({"*"}), frozenset({"expense:create"}))

    blocked = await engine.decide(request, reader)
    allowed = await engine.decide(request, writer)

    assert blocked.decision == Decision.BLOCK and blocked.passport is None
    assert allowed.decision == Decision.ALLOW and allowed.passport is not None


# ── Engine: Passport issuance rules ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_passport_only_for_allow():
    engine = DecisionEngine()
    confirm = await engine.decide(decision_request(llm={"confidence": 0.1}))
    assert confirm.decision != Decision.ALLOW
    assert confirm.passport is None and confirm.passport_id is None


@pytest.mark.asyncio
async def test_no_passport_in_shadow_mode():
    response = await DecisionEngine().decide(decision_request(shadow_mode=True))
    assert response.decision == Decision.ALLOW
    assert response.passport is None


@pytest.mark.asyncio
async def test_execution_record_stores_passport_id_not_token():
    engine = DecisionEngine()
    request = decision_request()
    response = await engine.decide(request)
    record = engine.get_execution_record(request, response)
    assert record.passport_id == response.passport_id
    assert record.passport_id != response.passport


@pytest.mark.asyncio
async def test_anonymous_caller_in_engine():
    read = decision_request().model_copy(update={
        "app_id": "claude-code", "plugin_id": "claude-code", "action_type": "Read", "payload": {"file_path": "README.md"},
    })
    response = await DecisionEngine().decide(read, ANONYMOUS)
    assert response.decision == Decision.CONFIRM
    assert "unauthenticated_caller" in response.audit_flags
    assert response.passport is None


# ── Keys: fail-closed, thumbprint kid, rotation ──────────────────────────────

def test_production_requires_private_key(monkeypatch):
    monkeypatch.delenv("AXG_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("AXG_ENV", "production")
    with pytest.raises(KeyConfigError):
        KeyManager()


def test_kid_is_rfc7638_thumbprint():
    expected = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_manager.get_jwks()["keys"][0]))
    assert expected is not None
    jwk = key_manager.get_jwks()["keys"][0]
    thumb_input = json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}, separators=(",", ":"), sort_keys=True)
    import base64
    digest = base64.urlsafe_b64encode(hashlib.sha256(thumb_input.encode()).digest()).rstrip(b"=").decode()
    assert key_manager.kid == digest == jwk["kid"]


def test_jwks_publishes_previous_keys(monkeypatch):
    retired = KeyManager()  # ephemeral, distinct key
    monkeypatch.setenv("AXG_PREVIOUS_PUBLIC_KEYS", json.dumps([retired.public_key.replace("\n", "\\n")]))
    kids = [k["kid"] for k in key_manager.get_jwks()["keys"]]
    assert kids == [key_manager.kid, retired.kid]


def test_previous_keys_must_be_a_list(monkeypatch):
    monkeypatch.setenv("AXG_PREVIOUS_PUBLIC_KEYS", '"single"')
    with pytest.raises(ValueError):
        key_manager.get_jwks()


# ── Plugin ids and remote policies ───────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("plugin_id", ["../finnorte", "finnorte/../x", "Finnorte", "a" * 65, "", "..\\x"])
async def test_invalid_plugin_ids_are_rejected(plugin_id):
    with pytest.raises(PluginLoadError, match="Invalid plugin id"):
        await PluginLoader()._load_local(plugin_id)


@pytest.mark.asyncio
async def test_remote_plugin_requires_allowlist(monkeypatch):
    monkeypatch.setenv("ENABLE_REMOTE_PLUGINS", "true")
    monkeypatch.setenv("AXG_REMOTE_PLUGIN_ALLOWLIST", "https://policies.example.com/")
    with pytest.raises(PluginLoadError, match="ALLOWLIST"):
        await PluginLoader().load("https://attacker.example/rules.json")


@pytest.mark.asyncio
async def test_signing_failure_downgrades_to_confirm(monkeypatch):
    def fail(**_):
        raise ValueError("hsm unavailable")

    monkeypatch.setattr("axg.engine.sign_decision", fail)
    response = await DecisionEngine().decide(decision_request())
    assert response.decision == Decision.CONFIRM
    assert response.passport is None
    assert "passport_signing_failed" in response.audit_flags


def test_jwks_endpoint_and_admin_reload(monkeypatch):
    client = TestClient(app)
    assert client.get("/.well-known/jwks.json").json()["keys"][0]["kid"] == key_manager.kid

    monkeypatch.setenv("AXG_ADMIN_TOKEN", "s3cret")
    assert client.post("/v1/plugins/reload", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/v1/plugins/reload", headers={"Authorization": "Bearer s3cret"}).json() == {"status": "reloaded"}


def test_python_sdk_ships_the_same_canonicalization():
    root = Path(__file__).resolve().parents[1]
    core = (root / "axg" / "canonical.py").read_bytes()
    sdk = (root / "sdks" / "axg-python-sdk" / "axg_python_sdk" / "canonical.py").read_bytes()
    assert core == sdk, "Keep axg/canonical.py and the SDK copy byte-identical"


ALLOWLIST = "https://policies.example.com, https://cdn.example.org/axg/, https://:bad, "


@pytest.mark.parametrize(
    "url",
    [
        "https://policies.example.com/rules.json",
        "https://POLICIES.example.com/finnorte/rules.json",
        "https://policies.example.com:443/rules.json",
        "https://cdn.example.org/axg/finnorte/rules.json",
        "https://cdn.example.org/axg",
    ],
)
def test_allowlist_accepts_same_origin_and_path(monkeypatch, url):
    from axg.plugin_loader import _is_allowlisted

    monkeypatch.setenv("AXG_REMOTE_PLUGIN_ALLOWLIST", ALLOWLIST)
    assert _is_allowlisted(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://policies.example.com.evil/rules.json",  # host suffix
        "https://evil.com/policies.example.com/rules.json",
        "https://policies.example.com@evil.com/rules.json",  # userinfo trick
        "http://policies.example.com/rules.json",  # scheme
        "https://policies.example.com:8443/rules.json",  # port
        "https://cdn.example.org/axgevil/rules.json",  # path boundary
        "https://cdn.example.org/other/rules.json",
        "https://cdn.example.org/axg/../secret/rules.json",  # dot segments
        "https://cdn.example.org/axg/%2e%2e/secret/rules.json",
        "https://policies.example.com:99999/rules.json",  # invalid port
        "not-a-url",
    ],
)
def test_allowlist_rejects_lookalikes(monkeypatch, url):
    from axg.plugin_loader import _is_allowlisted

    monkeypatch.setenv("AXG_REMOTE_PLUGIN_ALLOWLIST", ALLOWLIST)
    assert not _is_allowlisted(url)
