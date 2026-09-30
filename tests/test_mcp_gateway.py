"""AXG MCP gateway: a Streamable HTTP proxy that lets AXG decide every tools/call."""

import io
import json
import time
import urllib.parse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from axg.api import app as axg_app
from axg.crypto import key_manager
from integrations.agentcore import axg_interceptor
from integrations.mcp_gateway import axg_mcp_gateway as gateway
from tests.conftest import TEST_API_KEY, client_config

UPSTREAM = "http://upstream.test/mcp"


# --- a fake MCP server ------------------------------------------------------------------------------

def _upstream_app(seen: list) -> Starlette:
    async def mcp(request: Request) -> Response:
        seen.append({"method": request.method, "headers": dict(request.headers),
                     "body": json.loads(await request.body() or b"null")})
        if request.method == "DELETE":
            return Response(status_code=204)
        if request.method == "GET":
            return Response("event: message\ndata: {\"ping\": 1}\n\n", media_type="text/event-stream")
        message = seen[-1]["body"]
        if isinstance(message, dict) and message.get("method") == "initialize":
            data = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {"serverInfo": {"name": "fake"}}})
            return Response(f"event: message\ndata: {data}\n\n", media_type="text/event-stream",
                            headers={"mcp-session-id": "session-1", "x-internal": "hidden"})
        if isinstance(message, dict) and message.get("method") == "tools/call":
            return JSONResponse({"jsonrpc": "2.0", "id": message["id"],
                                 "result": {"content": [{"type": "text", "text": "done"}], "isError": False}})
        return JSONResponse({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})

    return Starlette(routes=[Route("/mcp", mcp, methods=["GET", "POST", "DELETE"])])


@pytest.fixture
def axg_env(monkeypatch):
    monkeypatch.setenv("AXG_URL", "https://axg.test")
    monkeypatch.setenv("AXG_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("AXG_APP_ID", "finnorte")
    monkeypatch.setenv("MCP_UPSTREAM_URL", UPSTREAM)
    monkeypatch.setenv("AXG_CLIENTS", json.dumps([client_config(client_id="mcp-gateway", app_ids=["finnorte"])]))
    client = TestClient(axg_app)
    decisions = []

    def fake_urlopen(request, timeout):
        decisions.append(json.loads(request.data))
        response = client.post(urllib.parse.urlparse(request.full_url).path, content=request.data,
                               headers=dict(request.header_items()))
        return io.BytesIO(response.content)

    monkeypatch.setattr(axg_interceptor.urllib.request, "urlopen", fake_urlopen)
    return decisions


@pytest.fixture
def static_gateway(axg_env, monkeypatch):
    monkeypatch.setenv("AXG_GATEWAY_AUTH", "static")
    monkeypatch.setenv("AXG_GATEWAY_AGENT_ID", "agent-42")
    monkeypatch.setenv("AXG_GATEWAY_TENANT_ID", "tenant_a")
    monkeypatch.setenv("AXG_GATEWAY_PERMISSIONS", "expense:create, ")
    monkeypatch.setenv("AXG_GATEWAY_USER_ID", "user-1")
    monkeypatch.setenv("MCP_UPSTREAM_AUTHORIZATION", "Bearer upstream-service-token")
    seen: list = []
    upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=_upstream_app(seen)))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.create_app(upstream)), base_url="http://gw")
    return client, seen, axg_env


def _call(arguments, meta=None, request_id=7):
    params = {"name": "create_expense", "arguments": arguments}
    if meta:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}


# --- behaviour -----------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_tool_traffic_passes_through_including_sse_and_sessions(static_gateway):
    client, seen, decisions = static_gateway
    init = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                             headers={"Authorization": "Bearer client-token", "Accept": "application/json, text/event-stream"})
    assert init.status_code == 200 and init.headers["content-type"].startswith("text/event-stream")
    assert init.headers["mcp-session-id"] == "session-1" and "x-internal" not in init.headers
    assert '"serverInfo"' in init.text
    assert seen[-1]["headers"]["authorization"] == "Bearer upstream-service-token"  # never the client's token
    assert (await client.get("/mcp")).text.startswith("event: message")
    assert (await client.delete("/mcp")).status_code == 204
    assert (await client.post("/mcp", json=[{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])).status_code == 200
    assert decisions == []  # AXG is only asked about tool calls


@pytest.mark.asyncio
async def test_allowed_call_reaches_the_tool_with_a_verifiable_passport(static_gateway):
    from axg_python_sdk import verify_mcp_tool_call

    client, seen, decisions = static_gateway
    arguments = {"merchant": "Padaria", "amount": 12.5, "currency": "EUR"}
    response = await client.post("/mcp", json=_call(arguments))
    assert response.json()["result"]["content"][0]["text"] == "done"

    forwarded = seen[-1]["body"]["params"]
    claims = verify_mcp_tool_call(forwarded["_meta"], "create_expense", forwarded["arguments"], "finnorte",
                                  tenant_id="tenant_a", public_key=key_manager.public_key)
    assert claims["azp"] == "mcp-gateway"
    assert decisions[0]["source"] == "mcp_gateway"
    assert decisions[0]["agent"] == {"id": "agent-42", "type": "agent", "permissions": ["expense:create"]}


@pytest.mark.asyncio
async def test_confirm_stops_at_the_gateway_and_the_approved_call_goes_through(static_gateway):
    from axg.approvals import ApprovalService
    from axg.auth import Caller
    from axg.engine import DecisionEngine
    from axg.models import ApprovalRequest

    client, seen, _ = static_gateway
    arguments = {"merchant": "Uber", "amount": 1500, "currency": "EUR"}
    blocked = (await client.post("/mcp", json=_call(arguments), headers={"MCP-Protocol-Version": "2026-07-28"})).json()["result"]
    assert blocked["isError"] and blocked["resultType"] == "complete"
    assert not [s for s in seen if s["body"].get("method") == "tools/call"]
    approval = blocked["_meta"]["io.axg/approval"]

    host = Caller("host", True, frozenset({"finnorte"}), frozenset({"approvals:approve"}))
    approved, _ = await ApprovalService(DecisionEngine().loader).submit(ApprovalRequest(
        ticket=approval["ticket"], actionable_payload=approval["actionable_payload"],
        approver={"id": "user-1", "role": "end_user"}), host)

    meta = {"io.axg/passport": approved.passport, "io.axg/actionable_payload": approved.actionable_payload}
    done = await client.post("/mcp", json=_call(arguments, meta))
    assert done.json()["result"]["content"][0]["text"] == "done"
    assert seen[-1]["body"]["params"]["_meta"]["io.axg/passport"] == approved.passport


@pytest.mark.asyncio
async def test_malformed_and_batched_tool_calls_are_refused(static_gateway):
    client, seen, _ = static_gateway
    assert (await client.post("/mcp", content=b"{not json")).json()["error"]["code"] == -32700
    batch = await client.post("/mcp", json=[_call({"amount": 1}), _call({"amount": 2}, request_id=8)])
    assert batch.status_code == 400 and "Batched tools/call" in batch.json()["error"]["message"]
    assert seen == []


@pytest.mark.asyncio
async def test_upstream_outage_is_a_jsonrpc_error(axg_env, monkeypatch):
    monkeypatch.setenv("AXG_GATEWAY_AUTH", "static")
    monkeypatch.setenv("AXG_GATEWAY_AGENT_ID", "a")
    monkeypatch.setenv("AXG_GATEWAY_TENANT_ID", "t")

    def down(request):
        raise httpx.ConnectError("down")

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(down))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.create_app(upstream)), base_url="http://gw")
    response = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 502 and response.json()["error"]["message"] == "The MCP server is unavailable"
    assert (await client.get("/health")).json()["status"] == "ok"


# --- caller identity -----------------------------------------------------------------------------------

def _rsa():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return key, public


def _token(key, **claims):
    body = {"iss": "https://idp.test", "aud": "axg-gateway", "exp": int(time.time()) + 60, "client_id": "agent-7",
            "tenant_id": "tenant_a", "scope": "expense:create", "sub": "user-1", **claims}
    return jwt.encode(body, key, algorithm="RS256")


@pytest.fixture
def jwt_gateway(axg_env, monkeypatch):
    key, public = _rsa()
    monkeypatch.setenv("AXG_GATEWAY_AUTH", "jwt")
    monkeypatch.setenv("AXG_GATEWAY_ISSUER", "https://idp.test")
    monkeypatch.setenv("AXG_GATEWAY_AUDIENCE", "axg-gateway")
    monkeypatch.setenv("AXG_GATEWAY_JWT_PUBLIC_KEY", public.replace("\n", "\\n"))
    seen: list = []
    upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=_upstream_app(seen)))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway.create_app(upstream)), base_url="http://gw")
    return client, key, axg_env


@pytest.mark.asyncio
async def test_jwt_callers_are_verified_before_anything_happens(jwt_gateway):
    client, key, decisions = jwt_gateway
    call = _call({"merchant": "Padaria", "amount": 5, "currency": "EUR"})

    missing = await client.post("/mcp", json=call)
    assert missing.status_code == 401 and missing.headers["WWW-Authenticate"] == "Bearer"
    forged_key, _ = _rsa()
    for token in ("garbage", _token(forged_key), _token(key, aud="another"), _token(key, exp=int(time.time()) - 5)):
        assert (await client.post("/mcp", json=call, headers={"Authorization": f"Bearer {token}"})).status_code == 401
    assert decisions == []

    ok = await client.post("/mcp", json=call, headers={"Authorization": f"Bearer {_token(key)}"})
    assert ok.json()["result"]["content"][0]["text"] == "done"
    assert decisions[-1]["agent"]["id"] == "agent-7" and decisions[-1]["tenant_id"] == "tenant_a"


def test_jwks_keys_are_resolved_per_token(axg_env, monkeypatch):
    key, public = _rsa()
    monkeypatch.setenv("AXG_GATEWAY_AUTH", "jwt")
    monkeypatch.setenv("AXG_GATEWAY_ISSUER", "https://idp.test")
    monkeypatch.setenv("AXG_GATEWAY_AUDIENCE", "axg-gateway")
    monkeypatch.setenv("AXG_GATEWAY_JWKS_URL", "https://idp.test/jwks")
    identity = gateway.CallerIdentity()
    monkeypatch.setattr(identity.jwks, "get_signing_key_from_jwt",
                        lambda _t: type("K", (), {"key": serialization.load_pem_public_key(public.encode())})())
    request = type("R", (), {"headers": {"authorization": f"Bearer {_token(key)}"}})()
    assert identity.claims(request)["client_id"] == "agent-7"


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"MCP_UPSTREAM_URL": ""}, "MCP_UPSTREAM_URL"),
        ({"AXG_GATEWAY_AUTH": "none"}, "must be 'jwt' or 'static'"),
        ({"AXG_GATEWAY_AUTH": "jwt", "AXG_GATEWAY_ISSUER": "i", "AXG_GATEWAY_AUDIENCE": "a"}, "JWKS_URL"),
        ({"AXG_GATEWAY_AUTH": "static", "AXG_GATEWAY_AGENT_ID": "a"}, "AXG_GATEWAY_TENANT_ID"),
    ],
)
def test_the_gateway_refuses_to_start_ungoverned(axg_env, monkeypatch, env, message):
    for name in ("AXG_GATEWAY_JWKS_URL", "AXG_GATEWAY_JWT_PUBLIC_KEY", "AXG_GATEWAY_TENANT_ID"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(gateway.GatewayConfigError, match=message):
        gateway.create_app()


def test_module_builds_the_app_lazily(axg_env, monkeypatch):
    monkeypatch.setenv("AXG_GATEWAY_AUTH", "static")
    monkeypatch.setenv("AXG_GATEWAY_AGENT_ID", "a")
    monkeypatch.setenv("AXG_GATEWAY_TENANT_ID", "t")
    assert isinstance(gateway.app, Starlette)
    with TestClient(gateway.create_app()) as client:  # runs the lifespan: the upstream client is closed on exit
        assert client.get("/health").json()["service"] == "axg-mcp-gateway"
    with pytest.raises(AttributeError):
        gateway.not_there  # noqa: B018
