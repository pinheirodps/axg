# Writing policies

A policy (a *plugin*) is a JSON file that tells AXG which actions exist, who may perform them, and which situations need a human or must be refused. Policies contain no code: they are validated data, so they are safe to review, diff and version like any other configuration.

AXG loads a policy from `<plugins dir>/<plugin_id>/rules.json`. The server image reads `/app/plugins`; mount your own directory there. In library mode, pass the directory to `PluginLoader(Path("..."))`.

## A complete example

[`examples/plugins/support_refunds/rules.json`](../examples/plugins/support_refunds/rules.json) governs a customer-support agent that can look up orders and issue refunds:

```json
{
  "$schema": "https://raw.githubusercontent.com/pinheirodps/axg/main/schemas/plugin_manifest.v1.schema.json",
  "schema_version": "axg.plugin_manifest.v1",
  "plugin": "support_refunds",
  "version": "1.0.0",
  "domain": "customer-support",
  "thresholds": {"allow_min_confidence": 0.85, "suggest_min_confidence": 0.6, "high_risk_threshold": 0.7},
  "actions": {
    "issue_refund": {"required_permissions": ["refunds:write"], "base_risk": 0.3},
    "lookup_order": {"base_risk": 0.05}
  },
  "rules": [
    {
      "id": "refund_above_limit",
      "description": "Refunds above 500 need a human.",
      "condition": {"all": [
        {"field": "action_type", "operator": "eq", "value": "issue_refund"},
        {"field": "payload.amount", "operator": "gt", "value": 500}
      ]},
      "decision": "CONFIRM",
      "reason": "Refunds above 500 require approval by a support lead.",
      "risk_delta": 0.3,
      "audit_flags": ["refund_above_limit"]
    },
    {
      "id": "refund_to_new_account",
      "description": "Never refund to a payment method added in the same conversation.",
      "condition": {"all": [
        {"field": "action_type", "operator": "eq", "value": "issue_refund"},
        {"field": "payload.destination_added_in_session", "operator": "eq", "value": true}
      ]},
      "decision": "BLOCK",
      "reason": "Refunds to a payment method added during the conversation are not allowed.",
      "risk_delta": 0.6
    }
  ],
  "uncertainty_gate": {
    "actions": ["issue_refund"],
    "uncertain_sources": ["chat"],
    "threshold": 0.7,
    "audit_flag": "refund_requires_confirmation",
    "reason": "The refund request was not understood with confidence. Confirm before paying out."
  }
}
```

With this policy:

| Request | Decision | Why |
|---|---|---|
| `lookup_order`, confidence 0.95 | `ALLOW` | No rule matches, confidence above `allow_min_confidence` |
| `issue_refund` of 80, agent holds `refunds:write`, confidence 0.95 | `ALLOW` | Permission held, no rule matches |
| `issue_refund` of 800 | `CONFIRM` | `refund_above_limit` |
| `issue_refund` to a card added in the session | `BLOCK` | `refund_to_new_account` |
| `issue_refund` by an agent without `refunds:write` | `BLOCK` | Missing permission |
| `issue_refund` from `chat` with an unknown intent | `CONFIRM` | Uncertainty gate |
| `delete_customer` (not declared) | `CONFIRM` | Undeclared actions always need confirmation |

The `$schema` line gives editors such as VS Code validation and completion. AXG ignores it.

## Top-level fields

| Field | Required | Description |
|---|---|---|
| `plugin` | yes | Policy id. Must match the directory name and the request's `plugin_id` |
| `version` | yes | Your version of the policy. Decisions and Passports record it as `plugin@version` |
| `domain` | yes | Free-form label (`customer-support`, `coding-agent`…) |
| `thresholds` | no | Confidence thresholds for the default decision, and the high-risk boundary |
| `actions` | no | The actions this policy knows, with required permissions and base risk |
| `rules` | no | Conditions that force a decision |
| `uncertainty_gate` | no | Writes that must be confirmed when the intent behind them is uncertain |
| `approval` | no | `default_role` (default `end_user`) and `ticket_ttl_seconds` (default 3600) for [human approvals](approvals.md) |

### `thresholds`

| Field | Default | Meaning |
|---|---|---|
| `allow_min_confidence` | 0.85 | With no rule outcome, `llm.confidence` at or above this gives `ALLOW` |
| `suggest_min_confidence` | 0.65 | At or above this (and below the allow threshold) gives `SUGGEST`; below gives `CONFIRM` |
| `high_risk_threshold` | 0.7 | `risk_score` at or above this is `high` risk. Also the base risk of undeclared actions |

### `actions`

Each key is an `action_type`. Declare every action your agents may take: undeclared actions always get `CONFIRM`.

| Field | Default | Meaning |
|---|---|---|
| `required_permissions` | `[]` | The agent must hold all of them (`agent.permissions`), capped by what its caller may grant. Missing any gives `BLOCK` |
| `base_risk` | 0.25 | Starting `risk_score` for this action |
| `approver_role` | plugin default | Role that approves this action when a human must decide |
| `required_context` | `[]` | [Context providers](signed-context.md) whose verified facts the action needs. Without them, `ALLOW` and `SUGGEST` become `CONFIRM` |

## Rules

A rule matches when its `condition` holds. Every matching rule contributes its `decision`, and the strictest wins (`BLOCK > CONFIRM > SUGGEST > ALLOW`).

| Field | Required | Description |
|---|---|---|
| `id` | yes | Stable identifier. It appears in responses, audit records and metrics |
| `description` | yes | What the rule is for, for reviewers |
| `condition` | yes | `all` (every condition), `any` (at least one), or both (both must hold) |
| `decision` | yes | `ALLOW`, `SUGGEST`, `CONFIRM` or `BLOCK` |
| `reason` | yes | Human-readable explanation returned to the caller |
| `confidence_penalty` | no | Subtracted from `final_confidence` (default by decision: 0.1, 0.25, 0.5) |
| `risk_delta` | no | Added to `risk_score` |
| `actionable_payload` | no | Fields merged into the payload that the Passport authorizes |
| `audit_flags` | no | Flags added to the response (default: the rule `id`) |
| `approver_role` | no | Role that must approve when this rule asks for a human; the strictest matched rule's role wins |

### Conditions

Each condition reads one `field` of the request with a dotted path and compares it with `value`:

| Operator | Matches when | Example |
|---|---|---|
| `eq`, `neq` | Equal, not equal | `{"field": "source", "operator": "eq", "value": "chat"}` |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison (non-numbers never match) | `{"field": "payload.amount", "operator": "gt", "value": 500}` |
| `in`, `not_in` | Value is (not) in the given list | `{"field": "action_type", "operator": "in", "value": ["Bash", "PowerShell"]}` |
| `contains` | Case-insensitive substring of a string, or exact member of a list | `{"field": "payload.command", "operator": "contains", "value": "rm -rf"}` |
| `exists` | The field is present | `{"field": "payload.coupon", "operator": "exists"}` |

A condition on a missing field never matches (except `exists`). An unknown operator is a validation error, so a typo cannot silently disable a rule.

Readable fields: `execution_id`, `tenant_id`, `app_id`, `plugin_id`, `user_id`, `source`, `action_type`, `shadow_mode`, `agent.id`, `agent.type`, `agent.permissions`, `llm.model`, `llm.confidence`, and anything under `payload.`, `context.`, `intent.` and `metadata.`. Facts from [signed context](signed-context.md) are under `verified.<provider>.`: prefer them over `context.` for anything the caller could misreport.

## Uncertainty gate

The gate protects writes that must never happen on a guess. When the action (or the action the proposer resolved) is listed in `actions` and the request's `uncertainty_score` reaches `threshold`, the decision is at least `CONFIRM`. The gate never lowers a `BLOCK`.

| Field | Default | Meaning |
|---|---|---|
| `actions` | `[]` | Gated writes. An empty list disables the gate |
| `uncertain_sources` | `whatsapp_bot`, `telegram_bot`, `chat` | Channels whose requests count as uncertain |
| `uncertain_source_suffixes` | `_bot` | Source suffixes that count as uncertain |
| `threshold` | 0.7 | Uncertainty score that triggers the gate |
| `audit_flag` | `write_requires_confirmation` | Flag added when the gate triggers |
| `reason` | generic text | Reason returned when the gate triggers |

## Validate, simulate, deploy

```bash
# Schema and semantic validation
axg validate-plugin --id support_refunds --dir examples/plugins

# Evaluate a request locally, without a server
axg simulate-decision --plugin support_refunds --payload examples/refund_request.json --dir examples/plugins
```

To roll out a policy change safely:

1. Validate it in CI with `axg validate-plugin`, and add tests with `axg simulate-decision` or `DecisionEngine`.
2. Bump `version`, so decisions and Passports record which policy produced them.
3. Trial it with `shadow_mode: true` on live traffic, and compare the decisions in your audit log or traces.
4. Deploy the file and reload without a restart: `POST /v1/plugins/reload` with `Authorization: Bearer $AXG_ADMIN_TOKEN`.

## Remote policies

AXG can load a policy from an HTTPS URL used as the `plugin_id`. This is off by default. Enable it with `ENABLE_REMOTE_PLUGINS=true` and list the allowed origins in `AXG_REMOTE_PLUGIN_ALLOWLIST`. Scheme, host and port must match exactly; a path in an entry scopes it. AXG refuses private and loopback addresses, pins the resolved IP and never follows redirects.

## Bundled policies

| Plugin | Domain | Highlights |
|---|---|---|
| [`claude-code`](../plugins/claude-code/rules.json) | Coding agents | Blocks destructive shell commands and piped remote scripts; confirms force pushes, deploys and secret files |
| [`finnorte`](../plugins/finnorte/rules.json) | Personal finance | Permissions per write, high-value and anomaly confirmations, financial uncertainty gate |
| [`pocket_lawyer`](../plugins/pocket_lawyer/rules.json) | Legal assistant | Blocks deleting original documents, promises of success and automatic court filings; confirms contracts and sensitive messages |
