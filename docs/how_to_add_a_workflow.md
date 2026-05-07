# How to Add a New Workflow to AXG

AXG is designed to be domain-agnostic. You can add support for new business domains (e.g., Legal, HR, IT) without modifying the AXG core code.

## 1. Define the Plugin Manifest
Create a new folder under `plugins/` (e.g., `plugins/legal/`).
Create a `rules.json` file following the `axg.plugin_manifest.v1` schema.

```json
{
  "schema_version": "axg.plugin_manifest.v1",
  "plugin": "legal_workflow",
  "version": "1.0.0",
  "domain": "legal",
  "thresholds": {
    "allow_min_confidence": 0.9,
    "suggest_min_confidence": 0.7,
    "high_risk_threshold": 0.8
  },
  "actions": {
    "sign_contract": {
      "required_permissions": ["legal_signatory"],
      "base_risk": 0.6
    }
  },
  "rules": [
    {
      "id": "RULE-001",
      "description": "Prevent high-value signing without human review",
      "condition": {
        "all": [
          { "field": "action_type", "operator": "eq", "value": "sign_contract" },
          { "field": "payload.value", "operator": "gt", "value": 50000 }
        ]
      },
      "decision": "CONFIRM",
      "reason": "Contracts over $50k require manual legal review."
    }
  ]
}
```

## 2. Validate the Plugin
Use the AXG CLI to ensure your manifest is syntactically correct:

```bash
axg validate-plugin --id legal_workflow --dir ./plugins
```

## 3. Simulate Decisions
Test your rules against sample payloads:

```bash
axg simulate-decision --plugin legal_workflow --payload samples/legal_request.json
```

## 4. Integrate with MUAI
In the MUAI backend, add a new `capability_manifest` that maps the intent to your new AXG plugin:

```json
{
  "capability_id": "legal.sign_contract",
  "axg_plugin_id": "legal_workflow",
  "axg_action_type": "sign_contract"
}
```

## 5. Observe the Audit Trail
Every decision made for your new workflow will automatically generate an `ExecutionRecord v1` in the audit logs, including:
- `input_hash`: Cryptographic proof of the request data.
- `passport_id`: Signed token for secure execution verification.
- `rules_triggered`: List of rules that influenced the decision.
- `shadow_mode`: Indication if the rule was running in evaluation mode.
