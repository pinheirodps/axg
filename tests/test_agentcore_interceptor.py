"""AgentCore Gateway REQUEST interceptor: AXG decides every MCP tool call (integration v0.4)."""

import base64
import io
import json
import urllib.error

import pytest
from fastapi.testclient import TestClient

from axg.api import app
from axg.crypto import key_manager
from integrations.agentcore import axg_interceptor as interceptor
from tests.conftest import TEST_API_KEY, client_config


def _jwt(claims: dict) -> str:
    enc = lambda part: base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.signature-checked-by-gateway"


def _event(method="tools/call", arguments=None, name="create_expense", claims=None):
    body = {"jsonrpc": "2.0", "id": 7, "method": method}
    if method == "tools/call":
        body["params"] = {"name": name, "arguments": arguments or {}}
    token = _jwt(claims or {"sub": "user-1", "client_id": "agent-42", "tenant_id": "tenant_a", "scope": "expense:create"})
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {"gatewayRequest": {"path": "/mcp", "httpMethod": "POST",
                                   "headers": {"Authorization": f"Bearer {token}"}, "body": body}},
    }


@pytest.fixture
def axg(monkeypatch):
    """Route the interceptor's HTTP call to the real AXG app, authenticated as its client."""
    monkeypatch.setenv("AXG_URL", "https://axg.test")
    monkeypatch.setenv("AXG_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("AXG_APP_ID", "finnorte")
    monkeypatch.setenv("AXG_CLIENTS", json.dumps([client_config(client_id="agentcore", app_ids=["finnorte"])]))
    client = TestClient(app)
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(json.loads(request.data))
        response = client.post("/v1/decisions", content=request.data, headers=dict(request.header_items()))
        return io.BytesIO(response.content)

    monkeypatch.setattr(interceptor.urllib.request, "urlopen", fake_urlopen)
    return calls


def _result(output):
    return output["mcp"]["transformedGatewayResponse"]["body"]["result"]


def test_allow_continues_with_a_verifiable_passport(axg):
    from axg_python_sdk import verify_mcp_tool_call

    arguments = {"merchant": "Padaria", "amount": 12.5, "currency": "EUR"}
    output = interceptor.handler(_event(arguments=arguments))

    body = output["mcp"]["transformedGatewayRequest"]["body"]
    meta = body["params"]["_meta"]
    assert meta["io.axg/decision"]["decision"] == "ALLOW"
    assert body["params"]["arguments"] == arguments  # unchanged without Cedar context

    # What the MCP tool does before acting:
    claims = verify_mcp_tool_call(meta, "create_expense", body["params"]["arguments"], "finnorte",
                                  tenant_id="tenant_a", public_key=key_manager.public_key)
    assert claims["azp"] == "agentcore"

    sent = axg[0]
    assert sent["agent"] == {"id": "agent-42", "type": "agent", "permissions": ["expense:create"]}
    assert sent["tenant_id"] == "tenant_a" and sent["source"] == "agentcore"


def test_confirm_short_circuits_with_readable_reason(axg):
    output = interceptor.handler(_event(arguments={"merchant": "Uber", "amount": 1500, "currency": "EUR"}))
    result = _result(output)
    assert result["isError"] is True
    assert result["structuredContent"]["axg"]["decision"] == "CONFIRM"
    assert result["content"][0]["text"].startswith("Confirmation required:")
    assert output["mcp"]["transformedGatewayResponse"]["body"]["id"] == 7


def test_block_is_reported_as_blocked(monkeypatch):
    monkeypatch.setenv("AXG_URL", "https://axg.test")
    monkeypatch.setenv("AXG_API_KEY", "k")
    monkeypatch.setenv("AXG_APP_ID", "finnorte")
    monkeypatch.setattr(interceptor, "ask_axg", lambda _req: {"decision": "BLOCK", "reason": "not permitted"})
    result = _result(interceptor.handler(_event(arguments={"amount": 1})))
    assert result["content"][0]["text"] == "Blocked by policy: not permitted"


def test_axg_unavailable_fails_closed(monkeypatch):
    monkeypatch.setenv("AXG_URL", "https://axg.down")
    monkeypatch.setenv("AXG_API_KEY", "k")
    monkeypatch.setenv("AXG_APP_ID", "finnorte")

    def down(request, timeout):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(interceptor.urllib.request, "urlopen", down)
    result = _result(interceptor.handler(_event(arguments={"amount": 1})))
    assert result["isError"] is True
    assert result["structuredContent"]["axg"]["decision"] == "UNAVAILABLE"


@pytest.mark.parametrize("method", ["tools/list", "initialize", "resources/read"])
def test_other_methods_pass_through(method, monkeypatch):
    monkeypatch.setattr(interceptor, "ask_axg", lambda _req: pytest.fail("AXG must not be called"))
    event = _event(method=method)
    output = interceptor.handler(event)
    assert output["mcp"]["transformedGatewayRequest"]["body"] == event["mcp"]["gatewayRequest"]["body"]


def test_cedar_context_is_optional(axg, monkeypatch):
    monkeypatch.setenv("AXG_CEDAR_CONTEXT", "true")
    output = interceptor.handler(_event(arguments={"merchant": "Padaria", "amount": 12.5, "currency": "EUR"}))
    params = output["mcp"]["transformedGatewayRequest"]["body"]["params"]
    decision = params["_meta"]["io.axg/decision"]
    assert params["arguments"]["axg"] == {"decision": "ALLOW", "risk_level": decision["risk_level"]}


def test_missing_or_garbage_token_uses_safe_defaults(monkeypatch):
    monkeypatch.setenv("AXG_APP_ID", "finnorte")
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "create_expense"}}
    for headers in ({}, {"authorization": "Bearer not.a-jwt"}, {"Authorization": "Basic abc"}):
        request = interceptor.build_decision_request(body, headers)
        assert request["tenant_id"] == "default"
        assert request["agent"] == {"id": "unknown-agent", "type": "agent", "permissions": []}
        assert request["payload"] == {}


def test_scopes_as_list_and_sub_fallback(monkeypatch):
    monkeypatch.setenv("AXG_APP_ID", "finnorte")
    headers = {"Authorization": f"Bearer {_jwt({'sub': 'svc-1', 'scope': ['a', 'b']})}"}
    request = interceptor.build_decision_request({"method": "tools/call", "params": {"name": "t"}}, headers)
    assert request["agent"] == {"id": "svc-1", "type": "agent", "permissions": ["a", "b"]}
