"""Stateless human approval: CONFIRM/SUGGEST carry a signed ticket that an approver exchanges for a Passport."""

import hashlib
import json
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from fastapi.testclient import TestClient

import axg.api
from axg import crypto
from axg.approvals import ApprovalRejected, ApprovalService
from axg.auth import ANONYMOUS, Caller
from axg.crypto import key_manager
from axg.engine import DecisionEngine
from axg.models import ApprovalRequest, Decision, DecisionRequest
from axg.plugin_loader import PluginLoader
from axg_python_sdk import AxgVerificationError, InMemoryReplayCache, verify_passport
from tests.conftest import TEST_API_KEY, client_config

AGENT = {"id": "agent-7", "type": "service", "permissions": ["expense:create"]}
HIGH_VALUE = {
    "execution_id": "exec-approval", "tenant_id": "tenant-a", "app_id": "finnorte", "plugin_id": "finnorte",
    "user_id": "user-1", "source": "api", "action_type": "create_expense",
    "payload": {"amount": 5000, "currency": "EUR"}, "agent": AGENT, "llm": {"confidence": 0.95},
}
TRUSTED = Caller("orchestrator", True, frozenset({"*"}), frozenset({"*"}))


async def _confirm(**overrides):
    response = await DecisionEngine().decide(DecisionRequest(**{**HIGH_VALUE, **overrides}), TRUSTED)
    assert response.decision == Decision.CONFIRM
    return response


def _approval(response, **overrides):
    data = {
        "ticket": response.approval.ticket,
        "actionable_payload": response.actionable_payload,
        "approver": {"id": "user-1", "role": "end_user"},
    }
    data.update(overrides)
    return ApprovalRequest(**data)


async def _submit(request, caller=TRUSTED):
    return await ApprovalService(DecisionEngine().loader).submit(request, caller)


# --- the challenge ---------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirm_carries_a_signed_ticket_bound_to_the_payload():
    response = await _confirm()
    challenge = response.approval

    assert challenge.required_role == "end_user"
    assert jwt.get_unverified_header(challenge.ticket)["typ"] == "axg-approval+jwt"
    claims = crypto.verify_approval_ticket(challenge.ticket)
    assert claims.jti == challenge.ticket_id and claims.exp == challenge.expires_at
    assert claims.payload_hash == crypto.hash_payload(response.actionable_payload)
    assert (claims.user_id, claims.agent_id, claims.decision) == ("user-1", "agent-7", "CONFIRM")
    assert claims.exp - claims.iat == 3600


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "caller"),
    [
        ({"payload": {"amount": 10, "currency": "EUR"}}, TRUSTED),  # ALLOW
        ({"agent": {**AGENT, "permissions": []}}, TRUSTED),  # BLOCK
        ({"shadow_mode": True}, TRUSTED),
        ({}, ANONYMOUS),
    ],
)
async def test_no_ticket_for_allow_block_shadow_or_anonymous(overrides, caller):
    response = await DecisionEngine().decide(DecisionRequest(**{**HIGH_VALUE, **overrides}), caller)
    assert response.approval is None


@pytest.mark.asyncio
async def test_ticket_signing_failure_leaves_a_plain_confirm():
    with patch("axg.engine.sign_approval_ticket", side_effect=RuntimeError("hsm down")):
        response = await DecisionEngine().decide(DecisionRequest(**HIGH_VALUE), TRUSTED)
    assert response.decision == Decision.CONFIRM and response.approval is None


def _policy(tmp_path, **plugin):
    policy = {
        "plugin": "refunds", "version": "1.0.0", "domain": "support",
        "actions": {"issue_refund": {"base_risk": 0.3, "approver_role": "support_lead"}, "note": {}},
        "rules": [{
            "id": "big_refund", "description": "d", "reason": "Big refund.", "decision": "CONFIRM",
            "approver_role": "finance_manager",
            "condition": {"all": [{"field": "payload.amount", "operator": "gt", "value": 1000}]},
        }],
        "approval": {"default_role": "tenant_admin", "ticket_ttl_seconds": 600},
        **plugin,
    }
    (tmp_path / "refunds").mkdir(exist_ok=True)
    (tmp_path / "refunds" / "rules.json").write_text(json.dumps(policy), encoding="utf-8")
    return DecisionEngine(loader=PluginLoader(tmp_path))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("action", "amount", "role"),
    [("issue_refund", 5000, "finance_manager"), ("issue_refund", 50, "support_lead"), ("note", 1, "tenant_admin")],
)
async def test_required_role_rule_then_action_then_default(tmp_path, action, amount, role):
    engine = _policy(tmp_path)
    request = DecisionRequest(
        execution_id="e", tenant_id="t", app_id="support", plugin_id="refunds", source="api",
        action_type=action, payload={"amount": amount}, llm={"confidence": 0.5},
    )
    response = await engine.decide(request, TRUSTED)
    assert response.approval.required_role == role
    claims = crypto.verify_approval_ticket(response.approval.ticket)
    assert claims.exp - claims.iat == 600


# --- approving -------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approval_yields_a_single_use_passport_for_the_same_payload():
    decision = await _confirm()
    response, record = await _submit(_approval(decision))

    assert response.outcome == "approved"
    assert response.passport_id == decision.approval.ticket_id
    claims = jwt.decode(response.passport, key_manager.public_key, algorithms=["RS256"], audience="finnorte")
    assert claims["decision"] == "ALLOW" and claims["jti"] == decision.approval.ticket_id
    assert claims["approval"] == {"ticket_id": decision.approval.ticket_id, "approver_id": "user-1", "approver_role": "end_user"}
    assert record.outcome == "approved" and record.passport_id == response.passport_id

    # Verifiers accept it once; a second Passport from the same ticket is a replay
    cache = InMemoryReplayCache()
    verify_passport(response.passport, response.actionable_payload, "finnorte", public_key=key_manager.public_key, replay_cache=cache)
    again, _ = await _submit(_approval(decision))
    with pytest.raises(AxgVerificationError) as replay:
        verify_passport(again.passport, again.actionable_payload, "finnorte", public_key=key_manager.public_key, replay_cache=cache)
    assert replay.value.code == "PASSPORT_REPLAYED"


@pytest.mark.asyncio
async def test_denial_is_recorded_without_a_passport():
    decision = await _confirm()
    response, record = await _submit(_approval(decision, outcome="deny"))
    assert (response.outcome, response.passport, response.actionable_payload) == ("denied", None, {})
    assert record.outcome == "denied" and record.passport_id is None


@pytest.mark.asyncio
async def test_a_ticket_is_never_a_passport():
    decision = await _confirm()
    with pytest.raises(AxgVerificationError) as exc:
        verify_passport(decision.approval.ticket, decision.actionable_payload, "finnorte", public_key=key_manager.public_key)
    assert exc.value.code == "DECISION_NOT_ALLOWED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "status"),
    [
        ({"actionable_payload": {"amount": 1, "currency": "EUR"}}, 409),
        ({"approver": {"id": "user-1", "role": "tenant_admin"}}, 403),
        ({"approver": {"id": "someone-else", "role": "end_user"}}, 403),
        ({"approver": {"id": "agent-7", "role": "end_user"}}, 403),
        ({"ticket": "not-a-jwt"}, 400),
    ],
)
async def test_approval_rejections(change, status):
    decision = await _confirm()
    with pytest.raises(ApprovalRejected) as exc:
        await _submit(_approval(decision, **change))
    assert exc.value.status_code == status


@pytest.mark.asyncio
async def test_agent_can_never_approve_its_own_action_even_as_the_right_role():
    decision = await _confirm(user_id=None)
    with pytest.raises(ApprovalRejected, match="own action"):
        await _submit(_approval(decision, approver={"id": "agent-7", "role": "end_user"}))
    # Without a user on the request, any end user other than the agent may approve
    response, _ = await _submit(_approval(decision, approver={"id": "user-9", "role": "end_user"}))
    assert response.outcome == "approved"


@pytest.mark.asyncio
async def test_a_passport_or_foreign_token_is_not_a_ticket():
    from axg.crypto import sign_decision

    passport, _ = sign_decision(
        execution_id="e", app_id="finnorte", tenant_id="t", decision="ALLOW", action_type="x",
        actionable_payload={}, client_id="c", policy="p@1",
    )
    foreign = jwt.encode({"iss": "axg-engine"}, "s" * 32, algorithm="HS256", headers={"typ": "axg-approval+jwt", "kid": "nope"})
    decision = await _confirm()
    for token in (passport, foreign):
        with pytest.raises(ApprovalRejected) as exc:
            await _submit(_approval(decision, ticket=token))
        assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_expired_ticket_is_rejected():
    decision = await _confirm()
    claims = jwt.decode(decision.approval.ticket, options={"verify_signature": False})
    claims["exp"] = claims["nbf"] - 1
    expired = jwt.encode(claims, key_manager.private_key, algorithm="RS256", headers={"kid": key_manager.kid, "typ": "axg-approval+jwt"})
    with pytest.raises(ApprovalRejected, match="expired"):
        await _submit(_approval(decision, ticket=expired))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("caller", "status"),
    [
        (ANONYMOUS, 401),
        (Caller("other-app", True, frozenset({"another"}), frozenset({"*"})), 403),
        (Caller("no-permission", True, frozenset({"*"}), frozenset({"expense:create"})), 403),
    ],
)
async def test_only_authorized_callers_submit_approvals(caller, status):
    decision = await _confirm()
    with pytest.raises(ApprovalRejected) as exc:
        await _submit(_approval(decision), caller)
    assert exc.value.status_code == status


@pytest.mark.asyncio
async def test_a_changed_or_removed_policy_needs_a_fresh_decision(tmp_path):
    engine = _policy(tmp_path)
    request = DecisionRequest(
        execution_id="e", tenant_id="t", app_id="support", plugin_id="refunds", source="api",
        action_type="issue_refund", payload={"amount": 5000}, llm={"confidence": 0.5},
    )
    decision = await engine.decide(request, TRUSTED)
    approval = _approval(decision, approver={"id": "fm-1", "role": "finance_manager"})

    _policy(tmp_path, version="2.0.0")
    with pytest.raises(ApprovalRejected, match="policy changed"):
        await ApprovalService(PluginLoader(tmp_path)).submit(approval, TRUSTED)

    (tmp_path / "refunds" / "rules.json").unlink()
    with pytest.raises(ApprovalRejected, match="no longer available"):
        await ApprovalService(PluginLoader(tmp_path)).submit(approval, TRUSTED)


@pytest.mark.asyncio
async def test_signing_failure_on_approval_asks_to_retry():
    decision = await _confirm()
    with patch("axg.approvals.sign_decision", side_effect=ValueError("hsm down")):
        with pytest.raises(ApprovalRejected) as exc:
            await _submit(_approval(decision))
    assert exc.value.status_code == 503


def test_tickets_from_a_retired_key_still_verify(monkeypatch):
    old_pem = key_manager.public_key
    assert key_manager.verification_key(key_manager.kid) == old_pem
    assert key_manager.verification_key("unknown") is None
    monkeypatch.setenv("AXG_PREVIOUS_PUBLIC_KEYS", json.dumps([old_pem]))
    assert key_manager.verification_key(crypto._rsa_jwk(old_pem)["kid"]) == old_pem


# --- HTTP ------------------------------------------------------------------------------------------


def test_api_approval_round_trip_is_audited(api_client, monkeypatch):
    recorded = AsyncMock()
    monkeypatch.setattr(axg.api.audit_manager, "record_decision", recorded)

    decision = api_client.post("/v1/decisions", json=HIGH_VALUE).json()
    assert decision["decision"] == "CONFIRM"
    body = {"ticket": decision["approval"]["ticket"], "actionable_payload": decision["actionable_payload"],
            "approver": {"id": "user-1", "role": "end_user"}}

    approved = api_client.post("/v1/approvals", json=body)
    assert approved.status_code == 200 and approved.json()["outcome"] == "approved"
    record = recorded.await_args_list[-1].args[0]
    assert record["schema_version"] == "axg.approval_record.v1" and record["client_id"] == "test-client"

    wrong_role = api_client.post("/v1/approvals", json={**body, "approver": {"id": "user-1", "role": "tenant_admin"}})
    assert wrong_role.status_code == 403
    assert "end_user" in wrong_role.json()["detail"]


def test_api_rejects_anonymous_and_rate_limits(monkeypatch):
    monkeypatch.setenv("AXG_AUTH_MODE", "optional")
    anonymous = TestClient(axg.api.app).post("/v1/approvals", json={
        "ticket": "x", "actionable_payload": {}, "approver": {"id": "u", "role": "end_user"},
    })
    assert anonymous.status_code == 401  # before the ticket is even parsed

    monkeypatch.setenv("AXG_CLIENTS", json.dumps([client_config(key_sha256=hashlib.sha256(TEST_API_KEY.encode()).hexdigest())]))
    monkeypatch.setattr(axg.api.rate_limiter, "check", lambda _client: 30)
    limited = TestClient(axg.api.app, headers={"Authorization": f"Bearer {TEST_API_KEY}"}).post("/v1/approvals", json={
        "ticket": "x", "actionable_payload": {}, "approver": {"id": "u", "role": "end_user"},
    })
    assert limited.status_code == 429 and limited.headers["Retry-After"] == "30"
