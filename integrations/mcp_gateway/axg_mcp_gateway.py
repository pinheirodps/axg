"""AXG MCP gateway: a Streamable HTTP proxy that puts AXG in front of any MCP server.

MCP client ──► gateway ──► MCP server (upstream)
                 │ tools/call → AXG decides (same core as the AgentCore interceptor)
                 │   ALLOW  → forwarded with the Passport and authorized payload in params._meta
                 │   CONFIRM / SUGGEST → tool result isError + _meta["io.axg/approval"] for the host
                 │   BLOCK / AXG down → tool result isError (fail closed)
                 │   call carrying a Passport → introspection, forwarded unchanged when valid
                 └ every other request and all responses (JSON or SSE) pass through unchanged

The gateway must be the only network path to the upstream server, and the tools should still
verify the Passport (``verify_mcp_tool_call``) before acting.

Configuration (environment variables), in addition to the AXG_* variables of the interceptor
(AXG_URL, AXG_API_KEY, AXG_APP_ID, AXG_PLUGIN_ID, AXG_TENANT_CLAIM, AXG_AGENT_CLAIM, AXG_TIMEOUT_SECONDS):

  MCP_UPSTREAM_URL            the upstream MCP endpoint, e.g. http://mcp-server:3000/mcp       (required)
  MCP_UPSTREAM_AUTHORIZATION  Authorization header sent upstream (the client's is never forwarded)
  AXG_GATEWAY_AUTH            how callers are identified (required):
      jwt     verify the caller's bearer JWT: AXG_GATEWAY_JWKS_URL or AXG_GATEWAY_JWT_PUBLIC_KEY (PEM),
              AXG_GATEWAY_ISSUER, AXG_GATEWAY_AUDIENCE; the claims map to tenant, agent and permissions
      static  one agent behind this gateway: AXG_GATEWAY_AGENT_ID, AXG_GATEWAY_TENANT_ID,
              AXG_GATEWAY_PERMISSIONS (comma separated), AXG_GATEWAY_USER_ID (optional)

Run:  uvicorn integrations.mcp_gateway.axg_mcp_gateway:app --port 8091
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

import anyio
import httpx
import jwt
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from integrations.agentcore import axg_interceptor

logger = logging.getLogger("axg.mcp_gateway")

SOURCE = "mcp_gateway"
# Request headers that describe the client-to-gateway hop, or carry the client's own credentials
DROPPED_REQUEST_HEADERS = {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "authorization"}
FORWARDED_RESPONSE_HEADERS = {"content-type", "mcp-session-id", "mcp-protocol-version", "cache-control"}
JWT_ALGORITHMS = ["RS256", "ES256", "PS256"]


class GatewayConfigError(RuntimeError):
    """The gateway is misconfigured; it refuses to start rather than run ungoverned."""


class Unauthorized(Exception):
    """The caller could not be identified."""


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise GatewayConfigError(f"{name} is required")
    return value


class CallerIdentity:
    """Turns an HTTP request into the claims AXG uses (tenant, agent, permissions)."""

    def __init__(self) -> None:
        self.mode = os.environ.get("AXG_GATEWAY_AUTH", "").strip().lower()
        if self.mode == "jwt":
            self.issuer = _required("AXG_GATEWAY_ISSUER")
            self.audience = _required("AXG_GATEWAY_AUDIENCE")
            self.public_key = os.environ.get("AXG_GATEWAY_JWT_PUBLIC_KEY", "").replace("\\n", "\n") or None
            jwks_url = os.environ.get("AXG_GATEWAY_JWKS_URL", "").strip()
            if not self.public_key and not jwks_url:
                raise GatewayConfigError("AXG_GATEWAY_JWKS_URL or AXG_GATEWAY_JWT_PUBLIC_KEY is required for jwt auth")
            self.jwks = jwt.PyJWKClient(jwks_url) if jwks_url and not self.public_key else None
        elif self.mode == "static":
            self.static_claims = {
                "client_id": _required("AXG_GATEWAY_AGENT_ID"),
                "tenant_id": _required("AXG_GATEWAY_TENANT_ID"),
                "scope": [p.strip() for p in os.environ.get("AXG_GATEWAY_PERMISSIONS", "").split(",") if p.strip()],
            }
            if os.environ.get("AXG_GATEWAY_USER_ID"):
                self.static_claims["sub"] = os.environ["AXG_GATEWAY_USER_ID"]
        else:
            raise GatewayConfigError("AXG_GATEWAY_AUTH must be 'jwt' or 'static'")

    def claims(self, request: Request) -> dict[str, Any]:
        if self.mode == "static":
            return dict(self.static_claims)
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise Unauthorized("Bearer token required")
        token = auth[7:].strip()
        try:
            key = self.public_key or self.jwks.get_signing_key_from_jwt(token).key
            return jwt.decode(token, key, algorithms=JWT_ALGORITHMS, audience=self.audience, issuer=self.issuer)
        except jwt.PyJWTError as exc:
            raise Unauthorized("Invalid token") from exc


def _upstream_headers(request: Request) -> dict[str, str]:
    headers = {k: v for k, v in request.headers.items() if k.lower() not in DROPPED_REQUEST_HEADERS}
    if os.environ.get("MCP_UPSTREAM_AUTHORIZATION"):
        headers["authorization"] = os.environ["MCP_UPSTREAM_AUTHORIZATION"]
    return headers


def _jsonrpc_error(request_id: Any, code: int, message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}, status_code=status)


def create_app(upstream: httpx.AsyncClient | None = None) -> Starlette:
    upstream_url = _required("MCP_UPSTREAM_URL")
    for name in ("AXG_URL", "AXG_API_KEY", "AXG_APP_ID"):
        _required(name)
    identity = CallerIdentity()
    client = upstream or httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=None))

    async def forward(request: Request, body: bytes | None = None) -> Response:
        upstream_request = client.build_request(
            request.method, upstream_url, params=request.query_params, headers=_upstream_headers(request),
            content=body if body is not None else await request.body(),
        )
        try:
            upstream_response = await client.send(upstream_request, stream=True)
        except httpx.HTTPError as exc:
            logger.error("MCP upstream unreachable: %s", type(exc).__name__)
            return _jsonrpc_error(None, -32603, "The MCP server is unavailable", status=502)
        headers = {k: v for k, v in upstream_response.headers.items() if k.lower() in FORWARDED_RESPONSE_HEADERS}
        return StreamingResponse(
            upstream_response.aiter_raw(), status_code=upstream_response.status_code, headers=headers,
            background=BackgroundTask(upstream_response.aclose),
        )

    async def mcp(request: Request) -> Response:
        try:
            claims = identity.claims(request)
        except Unauthorized as exc:
            return JSONResponse({"error": "unauthorized", "message": str(exc)}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        if request.method != "POST":
            return await forward(request)

        raw = await request.body()
        try:
            message = json.loads(raw)
        except ValueError:
            return _jsonrpc_error(None, -32700, "Parse error")
        if isinstance(message, list):
            if any(isinstance(m, dict) and m.get("method") == "tools/call" for m in message):
                return _jsonrpc_error(None, -32600, "Batched tools/call is not supported through the AXG gateway")
            return await forward(request, raw)
        if not isinstance(message, dict) or message.get("method") != "tools/call":
            return await forward(request, raw)

        # The interceptor core is synchronous (urllib): keep it off the event loop
        output = await anyio.to_thread.run_sync(
            axg_interceptor.govern_tools_call, message, claims, SOURCE, request.headers.get("mcp-protocol-version")
        )
        governed = output["mcp"]
        if "transformedGatewayResponse" in governed:
            return JSONResponse(governed["transformedGatewayResponse"]["body"])
        return await forward(request, json.dumps(governed["transformedGatewayRequest"]["body"]).encode("utf-8"))

    async def health(_: Request) -> Response:
        return JSONResponse({"status": "ok", "service": "axg-mcp-gateway"})

    @asynccontextmanager
    async def lifespan(_: Starlette):
        yield
        if upstream is None:
            await client.aclose()

    return Starlette(
        routes=[Route("/mcp", mcp, methods=["GET", "POST", "DELETE"]), Route("/health", health, methods=["GET"])],
        lifespan=lifespan,
    )


def __getattr__(name: str) -> Any:
    # ``app`` is built on first access, so importing this module never needs the environment
    if name == "app":
        return create_app()
    raise AttributeError(name)
