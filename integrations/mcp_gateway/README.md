# AXG MCP gateway

`axg_mcp_gateway.py` puts AXG in front of **any MCP server** that speaks Streamable HTTP. It is a small proxy: every `tools/call` is decided by AXG before it reaches the server, and all other traffic passes through untouched.

```text
MCP client (Claude, an agent framework, your app)
   │  Streamable HTTP
   ▼
AXG MCP gateway ──► AXG /v1/decisions, /v1/passports/introspect
   │  ALLOW   → forwarded; Passport + authorized payload in params._meta
   │  call already carrying a Passport → introspection → forwarded unchanged if active
   │  CONFIRM / SUGGEST → tool result isError + _meta["io.axg/approval"] (tool not called)
   │  BLOCK / AXG down  → tool result isError (fail closed)
   ▼
MCP server ── the tool verifies the Passport, then acts
```

The gateway reuses the decision core of the [AgentCore interceptor](../agentcore), so both integrations map calls, report decisions and handle approvals in the same way. Use the interceptor on AWS Bedrock AgentCore Gateway, and this gateway anywhere else.

## What passes through

| Traffic | Gateway behaviour |
|---|---|
| `initialize`, `tools/list`, resources, prompts, notifications, `GET` (SSE stream), `DELETE` (session end) | Forwarded unchanged; JSON and SSE responses are streamed back |
| `tools/call` | Decided by AXG first |
| A batch containing `tools/call` | Refused (`-32600`), so no call escapes governance |
| Session headers | `Mcp-Session-Id` and `MCP-Protocol-Version` are kept in both directions |
| The client's `Authorization` header | Never forwarded; the gateway sends `MCP_UPSTREAM_AUTHORIZATION` instead |

A result the gateway produces itself (for `CONFIRM`, `SUGGEST`, `BLOCK` or an outage) follows the client's protocol version: from MCP `2026-07-28` it includes `resultType: "complete"`, and for earlier versions it leaves the field out.

## Run

The gateway ships in the AXG image and needs no extra packages:

```bash
docker run -p 8091:8091 \
  -e MCP_UPSTREAM_URL=http://mcp-server:3000/mcp \
  -e AXG_URL=http://axg:8090 -e AXG_API_KEY="$GATEWAY_KEY" -e AXG_APP_ID=finnorte \
  -e AXG_GATEWAY_AUTH=jwt -e AXG_GATEWAY_ISSUER=https://idp.example.com \
  -e AXG_GATEWAY_AUDIENCE=mcp-gateway -e AXG_GATEWAY_JWKS_URL=https://idp.example.com/.well-known/jwks.json \
  ghcr.io/pinheirodps/axg:latest \
  uvicorn integrations.mcp_gateway.axg_mcp_gateway:app --host 0.0.0.0 --port 8091
```

From a checkout: `uvicorn integrations.mcp_gateway.axg_mcp_gateway:app --port 8091`. MCP clients then connect to `http://<gateway>:8091/mcp`; `GET /health` reports liveness.

On the AXG side, register the gateway in `AXG_CLIENTS`. `app_ids` is the Passport audience of the tools behind the gateway, and `permissions` caps the scopes agents can claim:

```json
[{"client_id": "mcp-gateway", "key_sha256": "<sha256 of GATEWAY_KEY>", "app_ids": ["finnorte"], "permissions": ["expense:create"]}]
```

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `MCP_UPSTREAM_URL` | yes | The MCP server endpoint, e.g. `http://mcp-server:3000/mcp` |
| `MCP_UPSTREAM_AUTHORIZATION` | no | `Authorization` header sent to the MCP server |
| `AXG_URL`, `AXG_API_KEY`, `AXG_APP_ID` | yes | AXG base URL, the gateway's key, and the Passport audience |
| `AXG_PLUGIN_ID` | no | Policy plugin (default: `AXG_APP_ID`) |
| `AXG_TIMEOUT_SECONDS` | no | Default `3` |
| `AXG_GATEWAY_AUTH` | yes | `jwt` or `static`, see below |

The gateway refuses to start when a required variable is missing, rather than running ungoverned.

### Identifying callers

**`jwt`**: each request carries a bearer token from your identity provider. The gateway verifies its signature (RS256, ES256 or PS256), issuer, audience and expiry, and maps its claims as the AgentCore interceptor does: `tenant_id` (or `AXG_TENANT_CLAIM`) is the tenant, `client_id` or `sub` (or `AXG_AGENT_CLAIM`) is the agent, `scope` becomes the agent's permissions, capped by the gateway's ceiling in `AXG_CLIENTS`. A missing or invalid token gets `401`.

| Variable | Meaning |
|---|---|
| `AXG_GATEWAY_ISSUER`, `AXG_GATEWAY_AUDIENCE` | Expected `iss` and `aud` |
| `AXG_GATEWAY_JWKS_URL` or `AXG_GATEWAY_JWT_PUBLIC_KEY` | Where the verification keys come from (a PEM key takes precedence) |

**`static`**: one agent sits behind this gateway, for example a sidecar next to a single agent. The identity comes from configuration, not from the request, so the gateway must not be reachable by anything else.

| Variable | Meaning |
|---|---|
| `AXG_GATEWAY_AGENT_ID`, `AXG_GATEWAY_TENANT_ID` | The agent and its tenant |
| `AXG_GATEWAY_PERMISSIONS` | Comma-separated permissions, capped by the ceiling in `AXG_CLIENTS` |
| `AXG_GATEWAY_USER_ID` | Optional end user, needed for `end_user` approvals |

## Security

- **Make the gateway the only path to the MCP server.** Put the server on a private network, or require `MCP_UPSTREAM_AUTHORIZATION`, so no client can skip AXG.
- **Keep verifying in the tools.** The gateway decides; the tool proves the decision with `verify_mcp_tool_call` / `verifyMcpToolCall` and a replay cache (see [In the MCP tool](../agentcore#in-the-mcp-tool-verify-before-acting)). A tool that verifies stays safe even if someone reaches it directly.
- **Fail closed.** If AXG is unreachable, tool calls are refused with `decision: UNAVAILABLE`; other traffic continues.

## Approvals

For `CONFIRM` and `SUGGEST`, the tool result carries `_meta["io.axg/approval"]`: the approval ticket, `required_role`, `expires_at` and the `actionable_payload`. The host application asks the right person and exchanges the ticket for a Passport with `submit_approval` / `submitApproval`. The call is then repeated with the Passport:

```python
from axg_python_sdk import submit_approval

result = await session.call_tool("create_expense", arguments)            # CONFIRM: isError, tool not called
approval = result.meta["io.axg/approval"]
# ... show approval["actionable_payload"] to the user; they approve ...
approved = submit_approval(AXG_URL, HOST_KEY, ticket=approval["ticket"],
                           actionable_payload=approval["actionable_payload"],
                           approver_id=user.id, approver_role="end_user")
await session.call_tool("create_expense", arguments, meta={
    "io.axg/passport": approved["passport"],
    "io.axg/actionable_payload": approved["actionable_payload"],
})                                                                       # runs once; a replay is refused by the tool
```

The gateway checks the Passport through [introspection](../../docs/passport.md#introspection) and requires the arguments to match the authorized payload; the tool's replay cache makes the approval single use. See [Human approvals](../../docs/approvals.md).

This flow is tested end to end with the official MCP Python SDK (`mcp` 2.2): an allowed call, a confirmation with its approval, the approved call, a refused replay and refused tampered arguments.
