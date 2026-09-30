"""submit_approval: exchange an AXG approval ticket for a Passport, or record a denial."""

import json

import httpx
import pytest

import axg_python_sdk
from axg_python_sdk import APPROVAL_META_KEY, AxgApprovalError, AxgClient, submit_approval

APPROVED = {"execution_id": "e1", "outcome": "approved", "passport": "jwt", "passport_id": "t1", "actionable_payload": {"a": 1}}


def _transport(status=200, body=APPROVED, seen=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if isinstance(body, Exception):
            raise body
        return httpx.Response(status, json=body) if isinstance(body, dict) else httpx.Response(status, text=body)

    return httpx.MockTransport(handler)


@pytest.fixture
def sync_axg(monkeypatch):
    def install(**kwargs):
        client = httpx.Client(transport=_transport(**kwargs))
        monkeypatch.setattr(axg_python_sdk.httpx, "post", client.post)
    return install


@pytest.fixture
def async_axg(monkeypatch):
    real = httpx.AsyncClient

    def install(**kwargs):
        monkeypatch.setattr(axg_python_sdk.httpx, "AsyncClient", lambda **kw: real(transport=_transport(**kwargs), **kw))
    return install


def test_approve_sends_the_ticket_payload_and_approver(sync_axg):
    seen = []
    sync_axg(seen=seen)
    result = submit_approval("https://axg.test/", "key", ticket="tk", actionable_payload={"a": 1},
                             approver_id="user-1", approver_role="end_user")
    assert result == APPROVED
    request = seen[0]
    assert str(request.url) == "https://axg.test/v1/approvals"
    assert request.headers["authorization"] == "Bearer key"
    assert json.loads(request.content) == {"ticket": "tk", "actionable_payload": {"a": 1},
                                           "approver": {"id": "user-1", "role": "end_user"}, "outcome": "approve"}


@pytest.mark.parametrize(("status", "body", "message"), [
    (403, {"detail": "This action must be approved by the role 'tenant_admin'"}, "tenant_admin"),
    (409, "plain text", "plain text"),
])
def test_refusals_raise_with_axg_status_and_reason(sync_axg, status, body, message):
    sync_axg(status=status, body=body)
    with pytest.raises(AxgApprovalError) as exc:
        submit_approval("https://axg.test", "key", ticket="tk", actionable_payload={}, approver_id="u", approver_role="r")
    assert exc.value.status_code == status and message in str(exc.value)


def test_outage_is_503(sync_axg):
    sync_axg(body=httpx.ConnectError("down"))
    with pytest.raises(AxgApprovalError) as exc:
        submit_approval("https://axg.test", "key", ticket="tk", actionable_payload={}, approver_id="u", approver_role="r")
    assert exc.value.status_code == 503


def test_outcome_must_be_approve_or_deny():
    with pytest.raises(ValueError):
        submit_approval("https://axg.test", "key", ticket="tk", actionable_payload={}, approver_id="u",
                        approver_role="r", outcome="maybe")


@pytest.mark.asyncio
async def test_async_client_denies_and_approves(async_axg):
    async_axg(body={"execution_id": "e1", "outcome": "denied", "passport": None, "passport_id": None, "actionable_payload": {}})
    client = AxgClient("https://axg.test", api_key="key")
    denied = await client.submit_approval(ticket="tk", actionable_payload={}, approver_id="u", approver_role="r", outcome="deny")
    assert denied["outcome"] == "denied"

    async_axg(status=403, body={"detail": "An agent cannot approve its own action"})
    with pytest.raises(AxgApprovalError, match="own action"):
        await client.submit_approval(ticket="tk", actionable_payload={}, approver_id="u", approver_role="r")

    async_axg(body=httpx.ReadTimeout("slow"))
    with pytest.raises(AxgApprovalError) as exc:
        await client.submit_approval(ticket="tk", actionable_payload={}, approver_id="u", approver_role="r")
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_async_client_needs_an_api_key():
    with pytest.raises(ValueError, match="api_key"):
        await AxgClient("https://axg.test").submit_approval(ticket="tk", actionable_payload={}, approver_id="u", approver_role="r")


def test_approval_meta_key_matches_the_integrations():
    assert APPROVAL_META_KEY == "io.axg/approval"
