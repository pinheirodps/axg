# AXG - Agent Execution Guard

Safe execution control plane for AI agent decisions.

> AI suggests. AXG decides.

AXG sits between probabilistic agents and deterministic systems. It validates proposed actions before they become real writes, API calls, financial records, or operational truths.

## Mission

Build a deterministic execution guard for AI agents:

- validate agent identity and permissions
- evaluate LLM confidence without calling an LLM
- evaluate contextual risk
- apply declarative policy rules
- return `ALLOW`, `SUGGEST`, `CONFIRM`, or `BLOCK`
- produce an auditable decision trace

## What AXG Is

AXG is a control plane for agent execution.

It is not:

- an LLM wrapper
- a prompt framework
- an agent framework
- a learning system

## Flow

```text
Agent / Bot / Tool
  -> MUAI interpretation layer
  -> AXG decision guard
  -> Target system such as FinNorte
```

## Current Implementation

Phase 1 is implemented:

- deterministic decision engine
- Pydantic input/output contracts
- declarative JSON plugin loader
- rule engine with simple operators
- FinNorte plugin
- FastAPI endpoint
- Docker image support
- GitHub Actions test/build pipeline
- unit tests with 100% package coverage

## Project Structure

```text
axg/
  api.py              # FastAPI app
  engine.py           # decision engine
  models.py           # request/response/plugin schemas
  plugin_loader.py    # JSON plugin loading and validation
  rules.py            # deterministic rule evaluator
plugins/
  finnorte/
    rules.json        # FinNorte policy plugin
tests/
  test_axg_core.py
```

## Decision API

Start the API:

```bash
python -m uvicorn axg.api:app --reload
```

Health:

```http
GET /health
```

Decision:

```http
POST /v1/decisions
```

Example request:

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
  "metadata": {
    "tenant_id": "tenant_001"
  }
}
```

Expected response:

```json
{
  "schema_version": "axg.decision.v1",
  "execution_id": "exec_001",
  "plugin_version": "finnorte@0.1.0",
  "decision": "CONFIRM",
  "scores": {
    "llm_confidence": 0.78,
    "final_confidence": 0.18,
    "risk_score": 1.0
  },
  "actionable_payload": {
    "proposed_action": "create_expense",
    "suggested_category": "Transport"
  },
  "human_readable_reason": "High value anomaly: this Uber expense is unusually large and must be confirmed before execution. Bot-originated high-value expenses require explicit user confirmation.",
  "audit_flags": ["high_value_anomaly", "transport_amount_anomaly", "bot_high_value"],
  "rules_triggered": [
    {
      "id": "high_value_transport_anomaly",
      "decision": "CONFIRM",
      "reason": "High value anomaly: this Uber expense is unusually large and must be confirmed before execution."
    }
  ],
  "metadata": {
    "tenant_id": "tenant_001"
  }
}
```

## Production Validation Cases

The first POC validates the flow:

```text
Bank Sync / Bot -> MUAI -> AXG -> FinNorte
```

Covered cases:

- `gastei 1500€ com Uber` -> `CONFIRM`
- `gastei 15€ com Uber` -> `ALLOW`
- `HONORATO PIZZA` misclassified as subscription -> `CONFIRM` or `SUGGEST`, never `ALLOW`
- recurring condominium payment with stable pattern -> `ALLOW`

The API accepts both early Phase 1 requests with `user_id` only and future Phase 2 requests with an explicit `agent` identity.

## Plugin Rules

Domain logic lives outside the core:

```text
plugins/finnorte/rules.json
```

Supported operators:

- `eq`
- `neq`
- `gt`
- `gte`
- `lt`
- `lte`
- `in`
- `not_in`
- `exists`
- `contains`

Supported condition groups:

- `all`
- `any`

No plugin code is executed. Plugins are data only.

## Fail-Safe Behavior

If a plugin is missing, invalid, or cannot be loaded:

```text
decision = CONFIRM
```

AXG never fails open to `ALLOW`.

## Testing

Install test dependencies, then run:

```bash
python -m pytest --cov=axg --cov-report=term-missing
```

Current result:

```text
28 passed
100% coverage
```

## Roadmap

Phase 1:

- core decision engine
- FinNorte plugin
- WhatsApp/Uber high-value validation

Phase 2:

- stronger agent identity and token model
- improved risk scoring
- structured audit sinks

Phase 3:

- plugin SDK
- multi-domain plugin catalog

Phase 4:

- AXG protocol formalization

## License

Apache 2.0
