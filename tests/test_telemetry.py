"""OpenTelemetry: one ``axg.decide`` span and decision metrics per evaluation, W3C trace propagation."""

import sys
from unittest.mock import AsyncMock

import pytest
from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

import axg.api
from axg import telemetry
from axg.auth import Caller
from axg.engine import DecisionEngine
from axg.models import AgentIdentity, Decision, DecisionRequest, LlmSignal

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT_SPAN_ID = "00f067aa0ba902b7"
TRACEPARENT = f"00-{TRACE_ID}-{PARENT_SPAN_ID}-01"


@pytest.fixture(scope="module")
def otel():
    """Install an in-memory SDK once: OpenTelemetry global providers can only be set once."""
    exporter = InMemorySpanExporter()
    reader = InMemoryMetricReader()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(MeterProvider(metric_readers=[reader]))
    return exporter, reader


@pytest.fixture
def spans(otel):
    exporter, _ = otel
    exporter.clear()
    return exporter


def _caller(client_id: str) -> Caller:
    """A distinct client per test keeps its metric data points apart from other tests."""
    return Caller(client_id, True, frozenset({"*"}), None)


def _request(**overrides) -> DecisionRequest:
    data = {
        "execution_id": "exec-otel",
        "tenant_id": "tenant-otel",
        "app_id": "finnorte",
        "plugin_id": "finnorte",
        "source": "api",
        "action_type": "create_expense",
        "payload": {"amount": 10, "currency": "EUR", "description": "coffee"},
        "agent": AgentIdentity(id="agent-7", type="service", permissions=["expense:create"]),
        "llm": LlmSignal(model="gpt-test", confidence=0.95),
    }
    data.update(overrides)
    return DecisionRequest(**data)


def _points(reader: InMemoryMetricReader, name: str, client_id: str) -> list:
    data = reader.get_metrics_data()
    return [
        point
        for resource_metrics in (data.resource_metrics if data else [])
        for scope_metrics in resource_metrics.scope_metrics
        for metric in scope_metrics.metrics
        if metric.name == name
        for point in metric.data.data_points
        if point.attributes.get("axg.client.id") == client_id or name == "axg.rules.triggered"
    ]


@pytest.mark.asyncio
async def test_decision_span_describes_the_decision_without_payload(spans):
    response = await DecisionEngine().decide(_request(), _caller("otel-allow"))
    assert response.decision == Decision.ALLOW

    (span,) = spans.get_finished_spans()
    attributes = span.attributes
    assert span.name == "axg.decide"
    assert attributes["axg.decision"] == "ALLOW"
    assert attributes["axg.policy"] == response.plugin_version
    assert attributes["axg.execution.id"] == "exec-otel"
    assert attributes["axg.tenant.id"] == "tenant-otel"
    assert attributes["axg.client.id"] == "otel-allow"
    assert attributes["axg.passport.id"] == response.passport_id
    assert attributes["gen_ai.agent.id"] == "agent-7"
    assert attributes["axg.proposal.model"] == "gpt-test"
    assert attributes["axg.risk.score"] == response.scores.risk_score
    assert span.status.status_code == StatusCode.UNSET
    # Decision metadata only: the payload, reason and Passport never reach telemetry
    exported = str(dict(attributes)) + str([event.attributes for event in span.events])
    for secret in ("coffee", response.passport, response.reason):
        assert secret not in exported


@pytest.mark.asyncio
async def test_triggered_rules_become_span_events_and_metrics(spans, otel):
    _, reader = otel
    response = await DecisionEngine().decide(
        _request(payload={"amount": 5000, "currency": "EUR"}), _caller("otel-rules")
    )
    assert response.rules_triggered

    (span,) = spans.get_finished_spans()
    events = [(event.name, event.attributes["axg.rule.id"]) for event in span.events]
    assert events == [("axg.rule.triggered", rule.id) for rule in response.rules_triggered]
    assert span.attributes["axg.rules.triggered"] == tuple(rule.id for rule in response.rules_triggered)
    assert span.status.status_code == StatusCode.UNSET  # a CONFIRM/BLOCK is not an error

    (decision_point,) = _points(reader, "axg.decisions", "otel-rules")
    assert decision_point.value == 1
    assert decision_point.attributes["axg.decision"] == response.decision.value
    assert "axg.tenant.id" not in decision_point.attributes  # metrics stay low-cardinality
    rule_ids = {point.attributes["axg.rule.id"] for point in _points(reader, "axg.rules.triggered", "")}
    assert {rule.id for rule in response.rules_triggered} <= rule_ids
    (duration_point,) = _points(reader, "axg.decision.duration", "otel-rules")
    assert duration_point.count == 1


@pytest.mark.asyncio
async def test_policy_failure_marks_the_span_as_error(spans):
    response = await DecisionEngine().decide(_request(plugin_id="does_not_exist"), _caller("otel-fail"))

    assert response.decision == Decision.CONFIRM
    (span,) = spans.get_finished_spans()
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description == "plugin_load_failed"


@pytest.mark.asyncio
async def test_unexpected_exception_is_recorded(spans, otel, monkeypatch):
    _, reader = otel
    engine = DecisionEngine()
    monkeypatch.setattr(engine, "_evaluate", AsyncMock(side_effect=ValueError("boom")))

    with pytest.raises(ValueError):
        await engine.decide(_request(), _caller("otel-crash"))

    (span,) = spans.get_finished_spans()
    assert span.status.status_code == StatusCode.ERROR
    assert span.events[0].name == "exception"
    assert _points(reader, "axg.decisions", "otel-crash") == []
    (duration_point,) = _points(reader, "axg.decision.duration", "otel-crash")
    assert duration_point.attributes["error.type"] == "ValueError"


def test_api_joins_the_caller_trace_and_links_the_audit_record(spans, api_client, monkeypatch):
    recorded = AsyncMock()
    monkeypatch.setattr(axg.api.audit_manager, "record_decision", recorded)

    response = api_client.post(
        "/v1/decisions",
        json=_request().model_dump(mode="json"),
        headers={"traceparent": TRACEPARENT},
    )

    assert response.status_code == 200
    (span,) = spans.get_finished_spans()
    assert format(span.context.trace_id, "032x") == TRACE_ID
    assert format(span.parent.span_id, "016x") == PARENT_SPAN_ID
    assert recorded.await_args.args[0].trace_id == TRACE_ID


def test_active_server_span_is_kept(spans):
    tracer = trace.get_tracer("test")
    with tracer.start_as_current_span("server") as server:
        with telemetry.continue_trace({"traceparent": TRACEPARENT}):
            assert telemetry.current_trace_id() == format(server.get_span_context().trace_id, "032x")


def test_no_trace_without_context(otel):
    assert telemetry.current_trace_id() is None


# --- configure_from_env ---------------------------------------------------------------------


@pytest.fixture
def fresh_process(monkeypatch):
    """Pretend no provider is installed yet and capture what configure_from_env installs."""
    from opentelemetry.sdk.metrics import export as metric_export
    from opentelemetry.sdk.trace import export as trace_export

    installed = {}
    monkeypatch.setattr(trace, "get_tracer_provider", trace.ProxyTracerProvider)
    monkeypatch.setattr(trace, "set_tracer_provider", lambda provider: installed.update(tracer=provider))
    monkeypatch.setattr(metrics, "set_meter_provider", lambda provider: installed.update(meter=provider))
    # No background export threads or network calls in tests
    monkeypatch.setattr(trace_export, "BatchSpanProcessor", SimpleSpanProcessor)
    monkeypatch.setattr(metric_export, "PeriodicExportingMetricReader", lambda exporter: InMemoryMetricReader())
    for variable in ("OTEL_SDK_DISABLED", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES", *telemetry.OTLP_ENDPOINT_VARIABLES):
        monkeypatch.delenv(variable, raising=False)
    yield installed
    for provider in installed.values():
        provider.shutdown()


def test_configure_installs_otlp_export_when_an_endpoint_is_set(fresh_process, monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")

    assert telemetry.configure_from_env() is True

    resource = fresh_process["tracer"].resource.attributes
    assert resource["service.name"] == "axg"
    assert resource["service.version"] == telemetry.AXG_VERSION
    assert fresh_process["meter"] is not None


def test_configure_respects_otel_service_name(fresh_process, monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://collector:4318/v1/traces")
    monkeypatch.setenv("OTEL_SERVICE_NAME", "axg-eu")

    assert telemetry.configure_from_env() is True
    assert fresh_process["tracer"].resource.attributes["service.name"] == "axg-eu"


@pytest.mark.parametrize(
    "environment",
    [{}, {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318", "OTEL_SDK_DISABLED": "true"}],
)
def test_configure_does_nothing_without_endpoint_or_when_disabled(fresh_process, monkeypatch, environment):
    for variable, value in environment.items():
        monkeypatch.setenv(variable, value)

    assert telemetry.configure_from_env() is False
    assert fresh_process == {}


def test_configure_keeps_an_installed_provider(otel, monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
    assert telemetry.configure_from_env() is False


def test_configure_asks_for_the_extra_when_the_sdk_is_missing(fresh_process, monkeypatch, caplog):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
    monkeypatch.setitem(sys.modules, "opentelemetry.exporter.otlp.proto.http.trace_exporter", None)

    assert telemetry.configure_from_env() is False
    assert "axg[otel]" in caplog.text
