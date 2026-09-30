# Observability

AXG instruments every decision with [OpenTelemetry](https://opentelemetry.io/). Decisions appear next to your agent and LLM spans in any OTLP backend: Jaeger, Grafana Tempo, Honeycomb, Datadog, Azure Monitor, or AWS X-Ray through ADOT.

## Enable export

**Server.** Set `OTEL_EXPORTER_OTLP_ENDPOINT`, for example `http://otel-collector:4318`. The image includes `axg[otel]` and exports traces and metrics over OTLP/HTTP. The standard variables apply: `OTEL_SERVICE_NAME` (default `axg`), `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_METRIC_EXPORT_INTERVAL`, `OTEL_SDK_DISABLED`… If a provider is already installed, for example by `opentelemetry-instrument`, AXG uses it.

**Library.** AXG depends only on `opentelemetry-api`. Without an SDK in the host process it records nothing. With one, `DecisionEngine.decide` spans join the host's current trace.

## Trace propagation

Send a W3C `traceparent` header with `POST /v1/decisions`, and the `axg.decide` span becomes a child of your span. Every audit record carries the `trace_id`, so a record leads straight to its trace.

## Signals

| Signal | Name | Content |
|---|---|---|
| Span | `axg.decide` | `axg.decision`, `axg.policy`, `axg.action.type`, `axg.plugin.id`, `axg.tenant.id`, `axg.app.id`, `axg.client.id`, `axg.execution.id`, `axg.source`, `axg.shadow_mode`, `axg.risk.score`, `axg.risk.level`, `axg.confidence.final`, `axg.uncertainty.score`, `axg.proposal.confidence`, `axg.proposal.model`, `axg.rules.triggered`, `axg.audit.flags`, `axg.context.verified`, `axg.passport.id`, `gen_ai.agent.id` |
| Span event | `axg.rule.triggered` | `axg.rule.id`, `axg.rule.decision`, once per matched rule |
| Span status | `ERROR` | Only when the policy could not be evaluated (`plugin_load_failed`, `passport_signing_failed`) or an exception escaped. `BLOCK` and `CONFIRM` are outcomes, not errors |
| Counter | `axg.decisions` | By `axg.decision`, `axg.plugin.id`, `axg.action.type`, `axg.client.id`, `axg.shadow_mode` |
| Counter | `axg.rules.triggered` | By `axg.rule.id`, `axg.rule.decision`, `axg.plugin.id` |
| Histogram | `axg.decision.duration` (seconds) | Same attributes as `axg.decisions`, plus `error.type` on failures |
| Span | `axg.approve` | `axg.approval.outcome` (approved, denied, rejected), `axg.approval.ticket_id`, `axg.approval.role`, `axg.policy`, `axg.action.type`, `axg.client.id`, and the rejection reason |
| Counter | `axg.approvals` | By `axg.approval.outcome` and `axg.client.id` |
| Span | `axg.introspect` | `axg.introspection.active`, `axg.client.id` |

Metric attributes are low-cardinality on purpose: tenant, execution and agent ids appear on spans only.

## Privacy

Telemetry carries decision metadata only. Payloads, actionable payloads, reasons, intents and Passports never leave AXG through spans or metrics.

## Useful alerts

| Alert | Query idea |
|---|---|
| Policy broken | Any `axg.decide` span with status `ERROR` |
| Unusual blocking | Rate of `axg.decisions{axg.decision="BLOCK"}` per `axg.client.id` above its baseline |
| Rule firing unexpectedly | `axg.rules.triggered` per `axg.rule.id` after a policy release |
| Latency | p99 of `axg.decision.duration` above 50 ms |

## Logs

Each decision also produces structured JSON logs (`axg.decision.request_received`, `axg.decision.evaluated`, `axg.decision.response_emitted`) with the same identifiers. Audit records are separate and are written to the configured [audit sinks](api.md#audit-records).
