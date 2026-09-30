# API and contracts

## Endpoints

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /v1/decisions` | `Authorization: Bearer <api key>` | Evaluate a proposed action |
| `POST /v1/passports/introspect` | `Authorization: Bearer <api key>` | Is a Passport valid for an action and payload? ([Introspection](passport.md#introspection)) |
| `POST /v1/approvals` | `Authorization: Bearer <api key>` with `approvals:approve` | Exchange an approved ticket for a Passport, or record a denial ([Human approvals](approvals.md)) |
| `GET /.well-known/jwks.json` | none | Current and retired public keys (JWKS) for Passport verification |
| `GET /v1/certs` | none | Current public key in PEM, with `kid` (legacy; prefer the JWKS) |
| `POST /v1/plugins/reload` | `Authorization: Bearer <AXG_ADMIN_TOKEN>` | Drop cached policies so the next request reloads them |
| `GET /health` | none | Liveness |

The OpenAPI document is served at `/openapi.json`, with interactive docs at `/docs`.

`POST /v1/decisions` accepts a W3C `traceparent` header. The decision span then joins the caller's trace (see [Observability](observability.md)).

## `POST /v1/decisions`

### Request

```json
{
  "execution_id": "refund-1",
  "tenant_id": "acme",
  "app_id": "support",
  "plugin_id": "support_refunds",
  "user_id": "customer-42",
  "agent": {"id": "support-agent", "type": "agent", "permissions": ["refunds:write"]},
  "source": "api",
  "action_type": "issue_refund",
  "payload": {"order_id": "A-1001", "amount": 800, "currency": "EUR"},
  "context": {},
  "llm": {"model": "any-model", "confidence": 0.93, "raw_output": {}},
  "intent": {"original": "refund", "resolved": "issue_refund", "fallback_used": false},
  "shadow_mode": false,
  "metadata": {"flow": "support_chat"}
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `execution_id` | string | yes | Your id for the action. Becomes the Passport `sub` |
| `tenant_id` | string | yes | Tenant the action is for. Bound into the Passport |
| `app_id` | string | yes | Application the action is for. Becomes the Passport `aud`. The caller must be allowed to act for it |
| `plugin_id` | string | yes | Policy to evaluate (a local id, or an allow-listed HTTPS URL) |
| `user_id` | string | no | End user on whose behalf the agent acts |
| `agent` | object | no | `id`, `type` (default `agent`), `permissions`. Required for actions that declare `required_permissions` |
| `source` | string | yes | Channel the request came from |
| `action_type` | string | yes | The proposed action |
| `payload` | object | no | Data of the action |
| `context` | object | no | Extra facts for rules (for example account history) |
| `llm` | object | no | `model`, `confidence` (0–1, default 0), `raw_output` |
| `intent` | object | no | Intent-resolution details used by the uncertainty score |
| `shadow_mode` | boolean | no | Evaluate without authorizing (no Passport) |
| `metadata` | object | no | Echoed back in the response; `metadata.flow` labels logs |

### Response

```json
{
  "schema_version": "axg.decision_response.v1",
  "execution_id": "refund-1",
  "plugin_version": "support_refunds@1.0.0",
  "decision": "CONFIRM",
  "passport": null,
  "passport_id": null,
  "scores": {
    "llm_confidence": 0.93,
    "final_confidence": 0.68,
    "risk_score": 0.6,
    "risk_level": "medium",
    "uncertainty_score": 0.0
  },
  "actionable_payload": {"order_id": "A-1001", "amount": 800, "currency": "EUR", "proposed_action": "issue_refund"},
  "reason": "Refunds above 500 require approval by a support lead.",
  "audit_flags": ["refund_above_limit"],
  "rules_triggered": [
    {"id": "refund_above_limit", "decision": "CONFIRM", "reason": "Refunds above 500 require approval by a support lead."}
  ],
  "shadow_mode": false,
  "metadata": {"flow": "support_chat"}
}
```

| Field | Description |
|---|---|
| `decision` | `ALLOW`, `SUGGEST`, `CONFIRM` or `BLOCK` |
| `plugin_version` | `plugin@version` that decided |
| `passport`, `passport_id` | The signed Passport and its `jti`, for `ALLOW` only |
| `scores` | See [Concepts](concepts.md#scores) |
| `actionable_payload` | What the Passport authorizes. Execute exactly this |
| `reason` | Human-readable explanation, safe to show to users |
| `audit_flags` | Machine-readable labels (rule ids, gates, `unauthenticated_caller`…) |
| `rules_triggered` | Matched rules with their decision and reason |
| `approval` | For `CONFIRM` and `SUGGEST`: `ticket`, `ticket_id`, `required_role`, `expires_at` |

### Errors

| Status | When |
|---|---|
| `401` | Missing or invalid API key (with `WWW-Authenticate: Bearer`) |
| `403` | The caller may not request decisions for this `app_id` |
| `413` | Body larger than `AXG_MAX_BODY_BYTES` |
| `422` | The request does not match the contract |
| `429` | Per-caller rate limit exceeded (with `Retry-After`) |

Policy problems are not HTTP errors: a policy that cannot be loaded returns `200` with `CONFIRM` and the flag `plugin_load_failed`.

## Contracts (JSON Schema)

The contracts are published as JSON Schema (draft 2020-12) in [`schemas/`](../schemas) and under stable URLs (`https://raw.githubusercontent.com/pinheirodps/axg/main/schemas/<name>.schema.json`):

| Schema | Describes |
|---|---|
| `decision_request.v1` | Request of `POST /v1/decisions` |
| `decision_response.v1` | Response of `POST /v1/decisions` |
| `passport_claims.v2` | Claims of the Passport JWT |
| `execution_record.v2` | Audit record written by the audit sinks |
| `plugin_manifest.v1` | Policy file (`rules.json`) |
| `approval_ticket_claims.v1` | Claims of an approval ticket |
| `approval_request.v1`, `approval_response.v1` | Request and response of `POST /v1/approvals` |
| `approval_record.v1` | Audit record of an approval or denial |
| `passport_introspection_request.v1`, `passport_introspection_response.v1` | `POST /v1/passports/introspect` |
| `execution_record.v1` | Superseded audit record, kept for existing consumers |

They are generated from the models (`python -m axg.schemas`), and CI fails when a committed schema drifts from its model. A contract change bumps its version and is listed in the [changelog](../CHANGELOG.md).

## Audit records

Each decision produces an `execution_record.v2`, written by the configured audit sinks:

- **File** (`AXG_AUDIT_FILE`): append-only JSONL with a hash chain (`prev_hash`, `record_hash`). `axg verify-audit --file <path>` reports the first edited, deleted or reordered line.
- **Webhook** (`AXG_AUDIT_WEBHOOK`, optional `AXG_AUDIT_WEBHOOK_TOKEN`): `POST` of each record, retried 3 times.

Records store the Passport `jti`, never the token, and a SHA-256 of the payload instead of the payload itself. `trace_id` links a record to its OpenTelemetry trace.
