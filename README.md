# AXG - Agent Execution Guard

Deterministic execution control for AI agent actions in real systems.

> AI suggests. AXG decides.

AXG sits between probabilistic AI interpretation and deterministic system writes. It evaluates risk, uncertainty, and policy constraints before any action is allowed to execute.

## Why AXG Exists

AI agents are probabilistic by nature. Production systems are not.

AXG is designed to prevent blind automation by enforcing deterministic decisions:

- **ALLOW**: safe to execute automatically
- **SUGGEST**: provide recommendation but avoid silent execution
- **CONFIRM**: require explicit human confirmation
- **BLOCK**: deny execution based on policy/permission

This pattern helps teams safely adopt AI in financial and operational workflows where mistakes are expensive.

## Architecture Overview

![Why Agents Need Execution Control](docs/images/why-agents-need-execution-control.png)

Execution flow:

```text
Agent/Bot/Tool -> MUAI (intent) -> AXG (execution guard) -> Core system write path
```

Conceptually, AXG is the policy and risk gate between intent understanding and persistence/actions.

## What AXG Is (and Is Not)

AXG **is**:

- a deterministic execution control plane
- a policy/risk decision engine
- an auditable guardrail layer for production workflows

AXG is **not**:

- an LLM wrapper
- a prompt orchestration framework
- an autonomous agent framework
- a learning/retraining system

## Core Capabilities

- Validates execution context (`app_id`, `plugin_id`, source, action).
- Supports agent identity and permission-based authorization.
- Applies declarative plugin rules (`plugins/<plugin_id>/rules.json`) with no dynamic code execution.
- Computes deterministic scoring:
  - `llm_confidence`
  - `final_confidence` (after penalties)
  - `risk_score`
  - `uncertainty_score`
- Handles uncertain intent/fallback paths safely for financial write operations.
- Returns a structured decision with:
  - human-readable reason
  - actionable payload
  - audit flags
  - triggered rules
- Emits structured logs for request/decision tracing.
- Fails safe to `CONFIRM` if plugin loading/validation fails.

## Decision Flow (Deterministic)

1. Load plugin by `plugin_id`.
2. Evaluate declarative rules against request data.
3. Compute confidence/risk/uncertainty scores.
4. Apply fail-safe uncertainty gate for risky financial writes.
5. Enforce action permissions.
6. Apply strongest rule decision by precedence.
7. Fallback to threshold-based decision when no rule applies.

Decision precedence:

```text
BLOCK > CONFIRM > SUGGEST > ALLOW
```

## API

Start locally:

```bash
python -m uvicorn axg.api:app --reload
```

Endpoints:

- `GET /health`
- `POST /v1/decisions`

### Example Request

```json
{
  "execution_id": "exec_001",
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
  "schema_version": "axg.decision.v1",
  "execution_id": "exec_001",
  "plugin_version": "finnorte@0.1.0",
  "decision": "CONFIRM",
  "scores": {
    "llm_confidence": 0.78,
    "final_confidence": 0.48,
    "risk_score": 0.9,
    "uncertainty_score": 0.0
  },
  "actionable_payload": {
    "proposed_action": "create_expense",
    "merchant": "Uber",
    "amount": 1500,
    "currency": "EUR",
    "suggested_category": "Transport"
  },
  "human_readable_reason": "High-value anomaly requires confirmation before execution.",
  "audit_flags": [
    "high_value_transaction",
    "requires_user_confirmation",
    "merchant_amount_anomaly"
  ],
  "rules_triggered": [
    {
      "id": "high_value_transport_anomaly",
      "decision": "CONFIRM",
      "reason": "High value anomaly: this expense is significantly higher than expected and must be confirmed."
    }
  ],
  "metadata": {
    "tenant_id": "tenant_001",
    "flow": "bot_expense_validation"
  }
}
```

## Plugin Model

Plugins are JSON-only policies. No plugin runtime code is executed.

Path convention:

```text
plugins/<plugin_id>/rules.json
```

Supported operators:

- `eq`, `neq`
- `gt`, `gte`, `lt`, `lte`
- `in`, `not_in`
- `exists`
- `contains`

Condition groups:

- `all`
- `any`

## Production Validation Scenarios Covered

Current tests and plugin behavior validate these scenarios:

- High-value Uber expense from bot/chat paths -> `CONFIRM`
- Normal expense with sufficient confidence -> `ALLOW`
- Unknown intent + fallback on financial writes -> `CONFIRM`
- Missing intent metadata on uncertain source for financial writes -> `CONFIRM`
- Merchant/category mismatch for subscription-like detection -> `SUGGEST` or `CONFIRM` (never blind `ALLOW`)
- Stable recurring condominium pattern -> `ALLOW`
- Missing permissions for required action -> `BLOCK`
- Unknown action in plugin -> `CONFIRM`
- Missing/invalid plugin -> fail-safe `CONFIRM`

## Project Structure

```text
axg/
  api.py              # FastAPI app and request/response logging
  engine.py           # deterministic decision orchestration
  models.py           # Pydantic schemas and enums
  plugin_loader.py    # plugin loading + schema validation
  rules.py            # rule operator evaluation
plugins/
  finnorte/
    rules.json        # FinNorte domain policy
tests/
  test_axg_core.py    # unit + API tests
```

## Fail-Safe Principles

- **Never fail open** to `ALLOW` on plugin/config issues.
- Unknown/high-uncertainty financial writes require confirmation.
- Permission failures produce deterministic `BLOCK`.
- Every decision includes machine-readable and human-readable audit context.

## Local Development

Install dependencies and run tests:

```bash
python -m pytest --cov=axg --cov-report=term-missing
```

Run API:

```bash
python -m uvicorn axg.api:app --reload
```

## Roadmap

### Phase 1 (implemented)

- Deterministic core decision engine
- FinNorte plugin
- FastAPI decision endpoint
- Structured audit logs
- Unit/API test suite with full package coverage

### Phase 2

- Stronger identity and token model
- More expressive risk scoring profiles
- Structured external audit sinks

### Phase 3

- Plugin SDK
- Multi-domain plugin catalog

### Phase 4

- AXG protocol formalization and interoperability profile

## Contributing

Contributions are welcome:

- policy/risk rule improvements
- documentation and examples
- tests and edge-case scenarios
- plugins for new domains

## License

Apache-2.0
