"""Passport introspection (RFC 7662-style): is this Passport valid for this action and payload?"""

import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient

import axg.api
from axg.crypto import APPROVAL_TICKET_TYP, key_manager, sign_decision
from tests.conftest import TEST_API_KEY, client_config

PAYLOAD = {"amount": 10, "currency": "EUR", "proposed_action": "create_expense"}


def _passport(**overrides):
    fields = dict(execution_id="e1", app_id="finnorte", tenant_id="t1", decision="ALLOW", action_type="create_expense",
                  actionable_payload=PAYLOAD, client_id="c", policy="finnorte@0.1.0")
    fields.update(overrides)
    return sign_decision(**fields)[0]


def _raw(claims, typ=None):
    headers = {"kid": key_manager.kid}
    if typ:
        headers["typ"] = typ
    return jwt.encode(claims, key_manager.private_key, algorithm="RS256", headers=headers)


def _claims(**overrides):
    now = int(time.time())
    claims = {"iss": "axg-engine", "sub": "e", "aud": "finnorte", "azp": "c", "iat": now, "nbf": now, "exp": now + 300,
              "jti": "j", "ver": 2, "tenant_id": "t1", "decision": "ALLOW", "action_type": "create_expense",
              "policy": "p@1", "payload_hash": "0" * 64}
    claims.update(overrides)
    return claims


def _introspect(api_client, **body):
    return api_client.post("/v1/passports/introspect", json=body)


def test_valid_passport_is_active_with_its_claims(api_client):
    response = _introspect(api_client, passport=_passport(), action_type="create_expense", actionable_payload=PAYLOAD)
    body = response.json()
    assert response.status_code == 200 and body["active"] is True
    assert body["claims"]["aud"] == "finnorte" and body["claims"]["decision"] == "ALLOW"


def test_introspection_without_action_or_payload_checks_the_token_only(api_client):
    assert _introspect(api_client, passport=_passport()).json()["active"] is True


@pytest.mark.parametrize(
    ("make_body", "reason"),
    [
        (lambda: {"passport": _passport(), "action_type": "create_income"}, "another action"),
        (lambda: {"passport": _passport(), "actionable_payload": {**PAYLOAD, "amount": 9}}, "Payload differs"),
        (lambda: {"passport": "garbage"}, "Invalid Passport"),
        (lambda: {"passport": _raw(_claims(exp=int(time.time()) - 10, nbf=int(time.time()) - 20))}, "expired"),
        (lambda: {"passport": _raw(_claims(decision="CONFIRM"))}, "Not an ALLOW"),
        (lambda: {"passport": _raw(_claims(), typ=APPROVAL_TICKET_TYP)}, "approval ticket"),
        (lambda: {"passport": jwt.encode(_claims(), "k" * 32, algorithm="HS256", headers={"kid": "someone-else"})},
         "Unknown signing key"),
    ],
)
def test_inactive_passports_say_why(api_client, make_body, reason):
    # Tokens are signed inside the test: other tests rotate the signing key
    result = _introspect(api_client, **make_body()).json()
    assert result["active"] is False and reason in result["reason"] and result["claims"] is None


def test_callers_learn_nothing_about_other_apps(monkeypatch):
    monkeypatch.setenv("AXG_CLIENTS", json.dumps([client_config(app_ids=["another-app"])]))
    client = TestClient(axg.api.app, headers={"Authorization": f"Bearer {TEST_API_KEY}"})
    result = client.post("/v1/passports/introspect", json={"passport": _passport()}).json()
    assert result == {"schema_version": "axg.passport_introspection_response.v1", "active": False, "reason": None, "claims": None}


def test_anonymous_callers_are_refused(monkeypatch):
    monkeypatch.setenv("AXG_AUTH_MODE", "optional")
    response = TestClient(axg.api.app).post("/v1/passports/introspect", json={"passport": _passport()})
    assert response.status_code == 401


def test_introspection_is_rate_limited(api_client, monkeypatch):
    monkeypatch.setattr(axg.api.rate_limiter, "check", lambda _client: 12)
    response = _introspect(api_client, passport=_passport())
    assert response.status_code == 429 and response.headers["Retry-After"] == "12"
