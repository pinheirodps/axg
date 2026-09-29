# Axg.AgentGovernance — AXG backend for the Microsoft Agent Governance Toolkit

`AxgPolicyBackend` implements the toolkit's `IExternalPolicyBackend`. Every `PolicyEngine.Evaluate` also asks AXG, which contributes domain policy, risk scoring, human confirmation and a **Passport** the tool can verify before acting.

Verified against `Microsoft.AgentGovernance` **5.0.0**, both with its real `PolicyEngine` (unit tests) and end to end against a live AXG.

```text
Agent → PolicyEngine.Evaluate(agentDid, context)
          ├─ native rules (YAML / Rego / Cedar)
          └─ AxgPolicyBackend ──► AXG /v1/decisions
                ALLOW + Passport → allowed
                SUGGEST / CONFIRM → denied, sink.RequiresApproval = true (ask a human)
                BLOCK → denied
                AXG error/unavailable → Error set → the toolkit denies (fail closed)
```

Toolkit behaviour measured on 5.0.0:
- An external **deny wins over native allow** rules.
- A backend `Error` denies.
- The context reaches the backend with the caller's keys plus `agent_did`.

## Usage

```csharp
using AgentGovernance.Policy;
using Axg.AgentGovernance;

var axg = new AxgPolicyBackend(new AxgPolicyBackendOptions
{
    BaseUrl = new Uri("https://axg.internal:8090"),
    ApiKey = Environment.GetEnvironmentVariable("AXG_API_KEY")!, // registered in AXG_CLIENTS
    AppId = "finnorte",                                           // Passport audience
});

var engine = new PolicyEngine();
engine.LoadYamlFile("policies.yaml");
engine.AddExternalBackend(axg);

var context = new Dictionary<string, object>
{
    ["tool_name"] = "create_expense",
    ["args"] = new Dictionary<string, object> { ["merchant"] = "Uber", ["amount"] = 12.5 },
    ["tenant_id"] = "tenant_a",
    ["permissions"] = new[] { "expense:create" },
};
var axgResult = AxgDecisionSink.Attach(context); // see "Getting the Passport"

var decision = engine.Evaluate("did:mesh:agent-1", context);
if (decision.Allowed)
{
    // Hand axgResult.Passport and axgResult.ActionablePayloadJson to the tool, which verifies them
}
else if (axgResult.RequiresApproval)
{
    // AXG asked for human confirmation: route to your approval flow
}
```

### Getting the Passport

Toolkit 5.0.0 does not copy backend metadata into `PolicyDecision`; its `external_backends` entries only carry `backend`, `allowed`, `reason`, `evaluation_ms` and `error`. So attach an `AxgDecisionSink` to each evaluation's context. The backend fills in:
- `Decision`, `RequiresApproval`;
- `Passport`, `PassportId`, `ActionablePayloadJson`;
- `ExecutionId`, `RiskLevel`, `Error`.

One sink per evaluation is thread-safe; nothing is shared between calls.

### Context mapping (configurable in `AxgPolicyBackendOptions`)

| Context key | AXG field |
|---|---|
| `agent_did` (added by the toolkit) | `agent.id` |
| `tool_name` (`ActionKey`) | `action_type`; declare it under `actions` in the AXG plugin |
| `args` (`PayloadKey`) | `payload` |
| `tenant_id` (`TenantKey`) | `tenant_id` (default `DefaultTenant`) |
| `permissions` (`PermissionsKey`) | `agent.permissions`, capped by the client ceiling in `AXG_CLIENTS` |

`source` is `"agt"` and `llm.confidence` is `1.0`: an explicit tool call is not an LLM guess, so AXG rules and permissions decide.

### Sync and async

`PolicyEngine.Evaluate` in 5.0.0 is synchronous. The backend's `Evaluate` uses real synchronous I/O (`HttpClient.Send`) instead of blocking on async code. `EvaluateAsync` is a genuinely async path, for hosts or future toolkit versions that call it.

## Build and test

```bash
dotnet test integrations/agt-dotnet
```
