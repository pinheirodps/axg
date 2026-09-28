# AXG - Agent Execution Guard

![AXG Hero](images/hero.png)

Deterministic execution control for AI agent actions in real systems.

> AI suggests. AXG decides.

AXG sits between probabilistic AI interpretation and deterministic system writes. It evaluates risk, uncertainty, and policy constraints before any action is allowed to execute.

## Status: Beta (v0.2)

AXG is in production as the decision layer of the MUAI ecosystem. v0.2 adds authenticated callers and Passport v2. The API may still change before 1.0. Read [Security Model](#security-model) before exposing AXG outside a private network.

## Why AXG Exists

AI agents are probabilistic by nature. Production systems are not.

AXG is designed to prevent blind automation by enforcing deterministic decisions:

- **ALLOW**: safe to execute automatically
- **SUGGEST**: provide recommendation but avoid silent execution
- **CONFIRM**: require explicit human confirmation
- **BLOCK**: deny execution based on policy/permission

## How AXG Fits In

![AXG Architecture](images/architecture.png)

In the broader ecosystem, MUAI is the gateway for AI capabilities and model fallback. AXG remains the deterministic gate before writes, external actions, or operational truth updates.

**MUAI LLM Gateway Synergy**: AXG is fully integrated with MUAI's LLM Gateway, ensuring that model-agnostic capabilities are governed by centralized security and risk policies.

Execution flow:

```text
App/Bot/Tool -> MUAI (intent + capabilities) -> AXG (execution guard) -> Core system write path
```

## What AXG Is (and Is Not)

AXG **is**:
- a deterministic execution control plane
- a policy/risk decision engine
- a cryptographic trust layer for autonomous actions (via AXG Passport)
- an auditable guardrail layer for production workflows

AXG is **not**:
- an LLM wrapper
- a prompt orchestration framework
- an autonomous agent framework

## Core Capabilities

- **Context Validation**: Validates `app_id`, `plugin_id`, source, and action.
- **Agent Identity**: Supports agent identity and permission-based authorization.
- **Declarative Rules**: Applies rules (`plugins/<plugin_id>/rules.json`) without dynamic code execution.
- **Deterministic Scoring**: Computes `llm_confidence`, `final_confidence`, `risk_score`, and `uncertainty_score`.
- **Authenticated Callers**: API keys (stored as SHA-256) bind each caller to the apps it may request decisions for and to the permissions it may grant its agents.
- **AXG Passport v2**: Issues short-lived RS256 signed `passport` tokens for `ALLOW` decisions only.
- **Payload Integrity**: The whole actionable payload is bound to the Passport by a canonical (RFC 8785-style) SHA-256 hash, identical in Python and Node.
- **Public Verification**: Exposes public keys through `/.well-known/jwks.json` (key rotation supported) and `/v1/certs`.
- **Audit Sinks**: Structured logging, file (`JSONL`), and webhook audit sinks.
- **CLI**: Tool for plugin validation and local decision simulation.

## AXG Passport

AXG Passport makes AXG a cryptographic trust layer. When an **authenticated** caller receives an `ALLOW` decision, the response includes a short-lived JWT `passport` signed with RS256. `SUGGEST`, `CONFIRM`, `BLOCK` and shadow-mode evaluations never carry one.

Consumer systems (e.g., FinNorte, Social Intent) verify this token before trusting an AI-proposed action. The token binds the authorized action to a deterministic hash of the payload, preventing tampering or unauthorized modification.

Passport v2 claims:

| Claim | Meaning |
|---|---|
| `iss`, `aud`, `sub` | `axg-engine`, the `app_id`, the `execution_id` |
| `iat`, `nbf`, `exp` | Issued at, valid from, expires (5 minutes) |
| `jti` | Unique id: verifiers can enforce single use (`replay_cache` / `replayCache` in the SDKs) |
| `ver` | `2` |
| `tenant_id` | Tenant the decision was made for |
| `azp` | Client that requested the decision |
| `decision`, `action_type` | Always `ALLOW`, plus the authorized action |
| `policy` | `plugin@version` that produced the decision |
| `payload_hash` | Canonical SHA-256 of the `actionable_payload` |

The SDKs (`sdks/axg-python-sdk`, `sdks/axg-node-sdk`) check signature, issuer, audience, validity window, decision, tenant, action type and payload hash. They also still verify v1 tokens.

### Passport Flow

```text
Agent / Bot / App
  -> MUAI interprets intent
  -> AXG evaluates policy and signs ALLOW decisions
  -> Consumer backend verifies Passport token
  -> System writes only if verification passes
```

## Decision Flow (Deterministic)

1. Load plugin by `plugin_id`.
2. Evaluate declarative rules against request data.
3. Compute confidence/risk/uncertainty scores.
4. Apply fail-safe uncertainty gate for risky financial writes.
5. Enforce action permissions.
6. Apply strongest rule decision by precedence.
7. Fallback to threshold-based decision when no rule applies.
8. Sign the actionable payload for `ALLOW` decisions (RS256).

Decision precedence:
`BLOCK > CONFIRM > SUGGEST > ALLOW`

## API

- `GET /health`: Health check.
- `POST /v1/decisions`: Main decision engine endpoint (`Authorization: Bearer <api key>`).
- `GET /.well-known/jwks.json`: Current and retired public keys for Passport verification.
- `GET /v1/certs`: Current public key in PEM (legacy).
- `POST /v1/plugins/reload`: Administrative plugin reload (requires `AXG_ADMIN_TOKEN`).

## Security Model

A Passport is only as trustworthy as the caller that asked for it, so:

- Every network caller authenticates with an API key. `AXG_AUTH_MODE=required` (default) rejects anonymous calls with `401`. `optional` exists for migrations only: anonymous calls are evaluated but can never receive `ALLOW` or a Passport.
- A caller may only request decisions for its own `app_ids` (the Passport audience), otherwise `403`.
- Agent permissions in the request are capped by the permissions granted to the caller.
- Without `AXG_PRIVATE_KEY`, AXG refuses to start when `AXG_ENV=production`; elsewhere it uses ephemeral development keys.
- Remote plugins are off by default. When enabled, they load only from `AXG_REMOTE_PLUGIN_ALLOWLIST` entries. Each entry is parsed and must match exactly on scheme, host and port. A path in the entry scopes it on a segment boundary, and dot segments are rejected.

Report vulnerabilities privately through GitHub Security Advisories on this repository, not in public issues.

### Configuration

| Variable | Purpose |
|---|---|
| `AXG_CLIENTS` | JSON list of callers: `[{"client_id": "muai", "key_sha256": "<sha256 of the key>", "app_ids": ["finnorte"], "permissions": ["*"]}]` |
| `AXG_AUTH_MODE` | `required` (default) or `optional` (migration only) |
| `AXG_ENV` | `production` makes a missing signing key fatal |
| `AXG_PRIVATE_KEY` / `AXG_PUBLIC_KEY` | RS256 signing key (PEM; `\n` escapes accepted) |
| `AXG_PREVIOUS_PUBLIC_KEYS` | JSON list of retired public keys still published in the JWKS during rotation |
| `AXG_ADMIN_TOKEN` | Enables `POST /v1/plugins/reload` |
| `ENABLE_REMOTE_PLUGINS`, `AXG_REMOTE_PLUGIN_ALLOWLIST` | Opt-in remote policies; comma-separated allowed origins, optionally with a path (`https://policies.example.com/axg/`) |
| `AXG_AUDIT_FILE`, `AXG_AUDIT_WEBHOOK`, `AXG_AUDIT_WEBHOOK_TOKEN` | Audit sinks |

Generate a client key hash with `python -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" <key>`.

### Example Request

```json
{
  "execution_id": "exec_001",
  "tenant_id": "tenant_001",
  "app_id": "finnorte",
  "plugin_id": "finnorte",
  "agent": {
    "id": "muai_whatsapp",
    "type": "service",
    "permissions": ["expense:create"]
  },
  "source": "whatsapp",
  "action_type": "create_expense",
  "payload": {
    "merchant": "Uber",
    "amount": 1500,
    "currency": "EUR",
    "proposed_action": "create_expense",
    "proposed_category": "Transport"
  },
  "context": {},
  "llm": {
    "model": "llama-3.3-70b",
    "confidence": 0.78,
    "raw_output": {}
  },
  "intent": {
    "original": "create_expense",
    "resolved": "create_expense",
    "fallback_used": false
  },
  "metadata": {
    "tenant_id": "tenant_001",
    "flow": "bot_expense_validation"
  }
}
```

### Example Response

```json
{
  "schema_version": "axg.decision_response.v1",
  "execution_id": "exec_001",
  "plugin_version": "finnorte@0.1.0",
  "decision": "CONFIRM",
  "passport": null,
  "passport_id": null,
  "scores": {
    "llm_confidence": 0.78,
    "final_confidence": 0.48,
    "risk_score": 0.9,
    "risk_level": "high",
    "uncertainty_score": 0.0
  },
  "actionable_payload": {
    "proposed_action": "create_expense",
    "merchant": "Uber",
    "amount": 1500,
    "currency": "EUR",
    "suggested_category": "Transport"
  },
  "reason": "This transaction has a high financial value and requires user confirmation before saving. This Uber expense is significantly higher than the user's normal Uber and transport spending patterns. Please confirm before saving.",
  "audit_flags": [
    "high_value_transaction",
    "requires_user_confirmation",
    "merchant_amount_anomaly"
  ],
  "rules_triggered": [
    {
      "id": "high_value_transaction",
      "decision": "CONFIRM",
      "reason": "This transaction has a high financial value and requires user confirmation before saving."
    },
    {
      "id": "merchant_amount_anomaly",
      "decision": "CONFIRM",
      "reason": "This Uber expense is significantly higher than the user's normal Uber and transport spending patterns. Please confirm before saving."
    }
  ],
  "metadata": {
    "tenant_id": "tenant_001",
    "flow": "bot_expense_validation"
  }
}
```

## Plugin Model

Plugins are JSON-only policies. Path: `plugins/<plugin_id>/rules.json`

## CLI

AXG ships with a CLI for local validation and simulation.

```bash
# Validate a plugin
axg validate-plugin --id finnorte --dir plugins

# Simulate a decision
axg simulate-decision --plugin finnorte --payload ./examples/request.json --dir plugins
```

## Project Structure

```text
axg/
  api.py              # FastAPI app, caller authentication and request/response logging
  audit.py            # file/webhook audit sinks
  auth.py             # API key clients, audience and permission ceilings
  canonical.py        # canonical JSON used for payload hashes (shared with the SDKs)
  cli.py              # plugin validation and decision simulation CLI
  crypto.py           # RS256 Passport v2 signing, JWKS and key rotation
  engine.py           # deterministic decision orchestration
  models.py           # Pydantic schemas and enums
  plugin_loader.py    # plugin loading + schema validation
  rules.py            # rule operator evaluation
plugins/
  finnorte/
    rules.json        # FinNorte domain policy
tests/
  test_audit.py       # audit sink tests
  test_axg_core.py    # engine + API tests
  test_cli.py         # CLI tests
  test_crypto.py      # Passport crypto tests
```

## Fail-Safe Principles

- **Never fail open** to `ALLOW` on plugin/config issues.
- Unknown/high-uncertainty financial writes require confirmation.
- Permission failures produce deterministic `BLOCK`.
- Signing failures produce deterministic `CONFIRM` or safer.
- Unauthenticated callers never receive `ALLOW` or a Passport.
- Admin operations fail closed when not configured.
- Every decision includes machine-readable and human-readable audit context.

## Local Development

```bash
pip install -e ".[test]"
python -m pytest --cov=axg --cov-report=term-missing --cov-fail-under=98
python -m uvicorn axg.api:app --reload
```

## License

Apache-2.0
