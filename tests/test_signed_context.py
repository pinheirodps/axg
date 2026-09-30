"""Signed context: rules read facts that trusted providers vouch for, not what the caller claims."""

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import axg.context as context
from axg.context import ContextConfigError, load_providers, verify_signed_context
from axg.engine import DecisionEngine
from axg.models import Decision, DecisionRequest
from axg.plugin_loader import PluginLoader

LEDGER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
IMPOSTOR = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISSUER = "https://ledger.internal"

RULES = [{
    "id": "monthly_limit", "description": "Verified monthly spend above the limit",
    "condition": {"all": [{"field": "verified.ledger.monthly_spend", "operator": "gt", "value": 1000}]},
    "decision": "BLOCK", "reason": "Monthly limit reached.",
}]


def _pem(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.fixture(autouse=True)
def providers(monkeypatch):
    monkeypatch.setenv("AXG_CONTEXT_PROVIDERS", json.dumps([{"id": "ledger", "issuer": ISSUER, "public_key": _pem(LEDGER)}]))


def _token(key=LEDGER, algorithm="RS256", **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": "axg", "iat": now, "exp": now + 120, "tenant_id": "t1", "sub": "user-1",
              "context": {"monthly_spend": 1500}}
    claims.update(overrides)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, key, algorithm=algorithm)


def _engine(tmp_path, **action):
    folder = tmp_path / "wallet"
    folder.mkdir()
    manifest = {"plugin": "wallet", "version": "1.0.0", "domain": "test", "rules": RULES,
                "actions": {"pay": {"base_risk": 0.1, **action}}}
    (folder / "rules.json").write_text(json.dumps(manifest), encoding="utf-8")
    return DecisionEngine(loader=PluginLoader(plugins_dir=tmp_path))


def _request(**extra) -> DecisionRequest:
    fields = dict(execution_id="e1", tenant_id="t1", app_id="wallet", plugin_id="wallet", user_id="user-1",
                  source="api", action_type="pay", payload={"amount": 10}, llm={"confidence": 0.99})
    fields.update(extra)
    return DecisionRequest(**fields)


# --- engine --------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rules_see_verified_facts(tmp_path):
    engine = _engine(tmp_path)
    request = _request(signed_context=[_token()])
    response = await engine.decide(request)
    assert response.decision == Decision.BLOCK and response.reason == "Monthly limit reached."
    assert response.verified_context == ["ledger"]
    assert engine.get_execution_record(request, response).verified_context == ["ledger"]

    under = await engine.decide(_request(signed_context=[_token(context={"monthly_spend": 200})]))
    assert under.decision == Decision.ALLOW


@pytest.mark.asyncio
async def test_callers_cannot_write_verified_facts(tmp_path):
    request = DecisionRequest.model_validate({**_request().model_dump(), "verified": {"ledger": {"monthly_spend": 0}},
                                              "context": {"monthly_spend": 5000}})
    assert "verified" not in request.model_dump()
    response = await _engine(tmp_path).decide(request)
    assert response.decision == Decision.ALLOW and response.verified_context == []


@pytest.mark.asyncio
async def test_required_context_raises_to_confirm_until_it_is_verified(tmp_path):
    engine = _engine(tmp_path, required_context=["ledger"])
    missing = await engine.decide(_request())
    assert missing.decision == Decision.CONFIRM and "verified_context_missing" in missing.audit_flags
    assert "verified context from ledger" in missing.reason
    assert missing.approval is not None  # a human can still approve

    forged = await engine.decide(_request(signed_context=[_token(key=IMPOSTOR, context={"monthly_spend": 1})]))
    assert forged.decision == Decision.CONFIRM
    assert {"signed_context_rejected", "verified_context_missing"} <= set(forged.audit_flags)

    verified = await engine.decide(_request(signed_context=[_token(context={"monthly_spend": 1})]))
    assert verified.decision == Decision.ALLOW and verified.passport


@pytest.mark.asyncio
async def test_missing_context_never_lowers_a_block(tmp_path):
    engine = _engine(tmp_path, required_context=["ledger"], required_permissions=["pay"])
    response = await engine.decide(_request(agent={"id": "bot", "permissions": []}))
    assert response.decision == Decision.BLOCK and "verified_context_missing" in response.audit_flags


def test_decisions_api_accepts_signed_context(api_client):
    body = _request(plugin_id="finnorte", app_id="finnorte", action_type="create_expense",
                    signed_context=[_token()]).model_dump()
    response = api_client.post("/v1/decisions", json=body).json()
    assert response["verified_context"] == ["ledger"]


# --- verification ----------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("make_token", "reason"),
    [
        (lambda: "not-a-jwt", "malformed token"),
        (lambda: _token(iss="https://elsewhere"), "unknown issuer"),
        (lambda: _token(iss=None), "unknown issuer"),
        (lambda: _token(key=IMPOSTOR), "ledger: InvalidSignatureError"),
        (lambda: _token(aud="another-service"), "ledger: InvalidAudienceError"),
        (lambda: _token(exp=int(time.time()) - 120), "ledger: ExpiredSignatureError"),
        (lambda: _token(tenant_id=None), "ledger: MissingRequiredClaimError"),
        (lambda: _token(iat=int(time.time()) - 3600, exp=int(time.time()) + 60), "ledger: too old"),
        (lambda: _token(tenant_id="t2"), "ledger: another tenant"),
        (lambda: _token(sub="user-2"), "ledger: another user"),
        (lambda: _token(context=["monthly_spend"]), "ledger: context is not an object"),
        (lambda: _token(key="a-shared-secret-of-32-bytes-long!", algorithm="HS256"), "ledger: InvalidAlgorithmError"),
    ],
)
def test_invalid_tokens_are_rejected_with_a_reason(make_token, reason):
    result = verify_signed_context([make_token()], "t1", "user-1")
    assert result.facts == {} and result.rejected == [reason]


def test_a_token_without_subject_fits_any_user_and_duplicates_are_ignored():
    result = verify_signed_context([_token(sub=None), _token(sub=None, context={"monthly_spend": 1})], "t1", None)
    assert result.facts == {"ledger": {"monthly_spend": 1500}} and result.rejected == ["ledger: duplicate"]
    assert verify_signed_context([], "t1", None).facts == {}


def test_jwks_providers_and_other_algorithms(monkeypatch):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setenv("AXG_CONTEXT_AUDIENCE", "axg-prod")
    monkeypatch.setenv("AXG_CONTEXT_PROVIDERS", json.dumps(
        [{"id": "kyc", "issuer": "https://kyc.internal", "jwks_url": "https://kyc.internal/jwks", "max_age_seconds": 60}]))
    provider = load_providers()["https://kyc.internal"]
    monkeypatch.setattr(provider.jwks, "get_signing_key_from_jwt", lambda _t: type("K", (), {"key": ec_key.public_key()}))
    token = _token(key=ec_key, algorithm="ES256", iss="https://kyc.internal", aud="axg-prod", context={"verified": True})
    assert verify_signed_context([token], "t1", "user-1").facts == {"kyc": {"verified": True}}
    assert load_providers() is load_providers()  # JWKS caches survive between requests


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ("{not json", "not valid JSON"),
        ('{"id": "ledger"}', "must be a JSON list"),
        ('["ledger"]', "must be a JSON object"),
        ('[{"id": "Ledger.v1", "issuer": "i", "public_key": "k"}]', "'id' must be"),
        ('[{"id": "ledger", "public_key": "k"}]', "needs an 'issuer'"),
        ('[{"id": "ledger", "issuer": "i", "public_key": "k", "max_age_seconds": 0}]', "max_age_seconds"),
        ('[{"id": "ledger", "issuer": "i"}]', "'jwks_url' or 'public_key'"),
        ('[{"id": "a", "issuer": "i", "public_key": "k"}, {"id": "b", "issuer": "i", "public_key": "k"}]', "unique"),
    ],
)
def test_bad_provider_configuration_is_reported(monkeypatch, config, message):
    monkeypatch.setenv("AXG_CONTEXT_PROVIDERS", config)
    with pytest.raises(ContextConfigError, match=message):
        load_providers()
    # At decision time a bad configuration verifies nothing, so required context stays missing
    result = verify_signed_context([_token()], "t1", "user-1")
    assert result.facts == {} and result.rejected == ["provider configuration invalid"]


def test_no_providers_configured(monkeypatch):
    monkeypatch.delenv("AXG_CONTEXT_PROVIDERS")
    assert load_providers() == {}
    assert verify_signed_context([_token()], "t1", "user-1").rejected == ["unknown issuer"]
    assert context.DEFAULT_MAX_AGE_SECONDS == 300
