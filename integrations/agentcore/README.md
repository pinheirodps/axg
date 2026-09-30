# AXG × AWS Bedrock AgentCore Gateway

`axg_interceptor.py` is a **REQUEST interceptor** for an AgentCore Gateway with MCP targets. Before any tool runs, AXG decides, and the tool receives a Passport it can verify.

```text
Agent ──MCP tools/call──► AgentCore Gateway
                            1. REQUEST interceptor (this Lambda) ──► AXG /v1/decisions
                                 ALLOW   → continue; Passport + authorized payload in params._meta
                                 call already carrying a Passport → AXG /v1/passports/introspect → continue if active
                                 CONFIRM / SUGGEST / BLOCK / AXG down → tool result isError (tool not called)
                            2. Cedar policy (runs after the interceptor)
                            3. MCP tool verifies the Passport, then acts
```

Gateway interceptors run before Cedar policy evaluation and can short-circuit a call. See [Types of interceptors](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html) and [Policy and Lambda interceptors](https://aws.amazon.com/blogs/machine-learning/secure-ai-agents-with-policy-and-lambda-interceptors-in-amazon-bedrock-agentcore-gateway/).

## Deploy

1. **AXG side.** Add a client for the interceptor to `AXG_CLIENTS`. `app_ids` is the Passport audience of the tools behind the gateway; `permissions` is the ceiling for agent scopes:
   ```json
   [{"client_id": "agentcore", "key_sha256": "<sha256 of the key>", "app_ids": ["finnorte"], "permissions": ["expense:create"]}]
   ```
2. **Lambda.** Python 3.12, handler `axg_interceptor.handler`, standard library only (zip the single file). Environment:

   | Variable | Required | Meaning |
   |---|---|---|
   | `AXG_URL` | yes | AXG base URL, reachable from the Lambda (VPC or AXGLayer) |
   | `AXG_API_KEY` | yes | The key registered in step 1 (use Secrets Manager or encrypted environment variables) |
   | `AXG_APP_ID` | yes | Passport audience |
   | `AXG_PLUGIN_ID` | no | Policy plugin (default: `AXG_APP_ID`) |
   | `AXG_TENANT_CLAIM` | no | JWT claim with the tenant (default: `tenant_id`) |
   | `AXG_AGENT_CLAIM` | no | JWT claim with the agent id (default: `client_id`, then `sub`) |
   | `AXG_TIMEOUT_SECONDS` | no | Default `3` |
   | `AXG_CEDAR_CONTEXT` | no | `true` adds `arguments.axg = {decision, risk_level}` for Cedar |

3. **Gateway.** Register the Lambda as the gateway's **REQUEST** interceptor with **`passRequestHeaders: true`**, so the interceptor can read the caller's token claims.

## How the call is mapped

| AgentCore | AXG `DecisionRequest` |
|---|---|
| `params.name` | `action_type`; declare it under `actions` in your plugin |
| `params.arguments` | `payload` |
| JWT `tenant_id` claim | `tenant_id` |
| JWT `client_id` / `sub` | `agent.id` |
| JWT `scope` | `agent.permissions`, capped by the client's ceiling |
| — | `source: "agentcore"`, `llm.confidence: 1.0`. An explicit tool call is not an LLM guess: rules and permissions decide. |

## In the MCP tool: verify before acting

Python:
```python
from axg_python_sdk import verify_mcp_tool_call, InMemoryReplayCache

replay = InMemoryReplayCache()  # use a shared store across replicas

def create_expense(arguments: dict, meta: dict):
    verify_mcp_tool_call(meta, "create_expense", arguments, app_id="finnorte",
                         jwks_url="https://axg.internal/.well-known/jwks.json", replay_cache=replay)
    ...  # AXG authorized exactly this call
```

TypeScript:
```ts
import { verifyMcpToolCall, InMemoryReplayCache } from 'axg-node-sdk';

await verifyMcpToolCall(request.params._meta, 'create_expense', request.params.arguments,
  { appId: 'finnorte', replayCache }, 'https://axg.internal/.well-known/jwks.json');
```

The helper checks five things:
- the Passport signature;
- audience, tenant and validity;
- that the Passport was issued **for this tool**;
- the payload hash;
- that **every argument received is identical** in the authorized payload.

Rules may add fields to the authorized payload, but they may never differ from the arguments.

## Confirmations and approvals

For `CONFIRM` and `SUGGEST`, the tool result carries `_meta["io.axg/approval"]`: AXG's approval ticket, `required_role`, `expires_at` and the `actionable_payload`. `_meta` is host metadata, not content the model reads. The host application stores it, asks the right person, and exchanges the ticket for a Passport (`submit_approval` / `submitApproval` in the SDKs). The agent then repeats the call with the Passport and the authorized payload in `params._meta`. The interceptor does not decide again: it checks the Passport with AXG's [introspection](../../docs/passport.md#introspection), requires every argument to match the authorized payload, and lets the call through unchanged. The tool verifies the Passport with a replay cache, which makes the approval single use. See [Human approvals](../../docs/approvals.md).

## Optional Cedar defense in depth

With `AXG_CEDAR_CONTEXT=true`, Cedar can require an AXG `ALLOW`:

```cedar
forbid(principal, action, resource)
when { !(context.input has axg) || context.input.axg.decision != "ALLOW" };
```

The injected `arguments.axg` is ignored by `verify_mcp_tool_call`.
