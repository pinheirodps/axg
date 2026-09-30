"""OpenTelemetry instrumentation for AXG decisions.

AXG depends only on ``opentelemetry-api``. Without an SDK every call below is a no-op, so a host
that embeds AXG as a library keeps full control of its own telemetry pipeline. The AXG server
installs ``axg[otel]`` and exports over OTLP when the standard ``OTEL_EXPORTER_OTLP_*`` variables
are set (see ``configure_from_env``).

Telemetry carries decision metadata only. Payloads, actionable payloads, reasons, intents and
Passports never leave the process through spans or metrics.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING, Any

from opentelemetry import context as otel_context
from opentelemetry import metrics, propagate, trace
from opentelemetry.trace import Span, StatusCode

if TYPE_CHECKING:
    from axg.auth import Caller
    from axg.models import DecisionRequest, DecisionResponse

logger = logging.getLogger(__name__)

try:
    AXG_VERSION = version("axg")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    AXG_VERSION = "0.0.0"

INSTRUMENTATION_SCOPE = "axg"
SPAN_NAME = "axg.decide"
RULE_EVENT = "axg.rule.triggered"
# Audit flags that mean AXG could not evaluate the policy as configured (the decision failed safe)
FAILURE_FLAGS = ("plugin_load_failed", "passport_signing_failed")
# Seconds: policy evaluation is in-memory, so the interesting range is sub-millisecond to ~1 s
DURATION_BUCKETS = [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
OTLP_ENDPOINT_VARIABLES = (
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
)

_tracer = trace.get_tracer(INSTRUMENTATION_SCOPE, AXG_VERSION)
_meter = metrics.get_meter(INSTRUMENTATION_SCOPE, AXG_VERSION)

decisions_counter = _meter.create_counter(
    "axg.decisions", unit="{decision}", description="Decisions returned by AXG."
)
rules_counter = _meter.create_counter(
    "axg.rules.triggered", unit="{rule}", description="Policy rules that matched a decision request."
)
duration_histogram = _meter.create_histogram(
    "axg.decision.duration",
    unit="s",
    description="Time AXG took to evaluate a decision request.",
    explicit_bucket_boundaries_advisory=DURATION_BUCKETS,
)

approvals_counter = _meter.create_counter(
    "axg.approvals", unit="{approval}", description="Approval submissions by outcome (approved, denied, rejected)."
)

class DecisionObservation:
    """Handle for the span of one decision; the engine reports the response through ``record``."""

    def __init__(self, span: Span) -> None:
        self.span = span
        self.response: DecisionResponse | None = None

    def record(self, response: DecisionResponse) -> None:
        self.response = response
        attributes: dict[str, Any] = {
            "axg.decision": response.decision.value,
            "axg.policy": response.plugin_version,
            "axg.risk.score": response.scores.risk_score,
            "axg.risk.level": response.scores.risk_level,
            "axg.confidence.final": response.scores.final_confidence,
            "axg.uncertainty.score": response.scores.uncertainty_score,
            "axg.rules.triggered": [rule.id for rule in response.rules_triggered],
            "axg.audit.flags": list(response.audit_flags),
            "axg.context.verified": list(response.verified_context),
        }
        if response.passport_id:
            attributes["axg.passport.id"] = response.passport_id
        self.span.set_attributes(attributes)

        for rule in response.rules_triggered:
            self.span.add_event(RULE_EVENT, {"axg.rule.id": rule.id, "axg.rule.decision": rule.decision.value})

        failures = [flag for flag in response.audit_flags if flag in FAILURE_FLAGS]
        if failures:
            # BLOCK/CONFIRM are correct outcomes; only a policy that could not be evaluated is an error
            self.span.set_status(StatusCode.ERROR, ", ".join(failures))


def _request_attributes(request: DecisionRequest, caller: Caller) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "axg.execution.id": request.execution_id,
        "axg.tenant.id": request.tenant_id,
        "axg.app.id": request.app_id,
        "axg.plugin.id": request.plugin_id,
        "axg.action.type": request.action_type,
        "axg.source": request.source,
        "axg.client.id": caller.client_id,
        "axg.shadow_mode": request.shadow_mode,
        "axg.proposal.confidence": request.llm.confidence,
    }
    if request.llm.model:
        attributes["axg.proposal.model"] = request.llm.model
    if request.agent:
        attributes["gen_ai.agent.id"] = request.agent.id
    return attributes


def _metric_attributes(request: DecisionRequest, caller: Caller) -> dict[str, Any]:
    """Low-cardinality attributes only: never tenant, execution or agent ids."""
    return {
        "axg.plugin.id": request.plugin_id,
        "axg.action.type": request.action_type,
        "axg.client.id": caller.client_id,
        "axg.shadow_mode": request.shadow_mode,
    }


@contextmanager
def observe_decision(request: DecisionRequest, caller: Caller) -> Iterator[DecisionObservation]:
    """Span ``axg.decide`` plus decision metrics around one evaluation."""
    started = time.perf_counter()
    metric_attributes = _metric_attributes(request, caller)
    with _tracer.start_as_current_span(SPAN_NAME, attributes=_request_attributes(request, caller)) as span:
        observation = DecisionObservation(span)
        try:
            yield observation
        except Exception as exc:
            metric_attributes["error.type"] = type(exc).__qualname__
            raise
        finally:
            response = observation.response
            if response is not None:
                metric_attributes["axg.decision"] = response.decision.value
                decisions_counter.add(1, metric_attributes)
                for rule in response.rules_triggered:
                    rules_counter.add(
                        1,
                        {
                            "axg.plugin.id": request.plugin_id,
                            "axg.rule.id": rule.id,
                            "axg.rule.decision": rule.decision.value,
                        },
                    )
            duration_histogram.record(time.perf_counter() - started, metric_attributes)


@contextmanager
def observe_approval(caller: Caller) -> Iterator[dict[str, Any]]:
    """Span ``axg.approve`` and the ``axg.approvals`` counter; the caller fills the yielded dict."""
    outcome: dict[str, Any] = {"axg.approval.outcome": "rejected"}
    with _tracer.start_as_current_span("axg.approve", attributes={"axg.client.id": caller.client_id}) as span:
        try:
            yield outcome
        finally:
            span.set_attributes(outcome)
            approvals_counter.add(
                1, {"axg.client.id": caller.client_id, "axg.approval.outcome": outcome["axg.approval.outcome"]}
            )


@contextmanager
def observe_introspection(caller: Caller) -> Iterator[dict[str, Any]]:
    """Span ``axg.introspect``; the caller sets ``axg.introspection.active`` in the yielded dict."""
    outcome: dict[str, Any] = {"axg.introspection.active": False}
    with _tracer.start_as_current_span("axg.introspect", attributes={"axg.client.id": caller.client_id}) as span:
        try:
            yield outcome
        finally:
            span.set_attributes(outcome)


@contextmanager
def continue_trace(carrier: Mapping[str, str]) -> Iterator[None]:
    """Join the caller's W3C trace (``traceparent``/``tracestate`` in ``carrier``).

    Skipped when a span is already active: server auto-instrumentation has then extracted the
    same context and opened its own span, which AXG's span must stay under.
    """
    if trace.get_current_span().get_span_context().is_valid:
        yield
        return
    token = otel_context.attach(propagate.extract(carrier))
    try:
        yield
    finally:
        otel_context.detach(token)


def current_trace_id() -> str | None:
    """W3C trace id of the active context (32 hex chars), or None when there is no trace."""
    span_context = trace.get_current_span().get_span_context()
    return format(span_context.trace_id, "032x") if span_context.is_valid else None


def configure_from_env() -> bool:
    """Install the OpenTelemetry SDK with OTLP/HTTP exporters when an OTLP endpoint is configured.

    Used by the AXG server only. Does nothing when ``OTEL_SDK_DISABLED=true``, when no
    ``OTEL_EXPORTER_OTLP_*ENDPOINT`` is set, or when a provider is already installed (for
    example by ``opentelemetry-instrument``). All other ``OTEL_*`` variables (headers, protocol
    settings, ``OTEL_SERVICE_NAME``, ``OTEL_RESOURCE_ATTRIBUTES``) are honoured by the SDK.
    """
    if os.environ.get("OTEL_SDK_DISABLED", "").strip().lower() == "true":
        return False
    if not any(os.environ.get(variable) for variable in OTLP_ENDPOINT_VARIABLES):
        return False
    if not isinstance(trace.get_tracer_provider(), trace.ProxyTracerProvider):
        logger.info("OpenTelemetry provider already installed; AXG uses it as is")
        return False

    try:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning("OTLP endpoint is set but the OpenTelemetry SDK is missing: pip install 'axg[otel]'")
        return False

    attributes = {SERVICE_VERSION: AXG_VERSION}
    if not os.environ.get("OTEL_SERVICE_NAME") and "service.name=" not in os.environ.get("OTEL_RESOURCE_ATTRIBUTES", ""):
        attributes[SERVICE_NAME] = "axg"
    resource = Resource.create(attributes)

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(
        MeterProvider(resource=resource, metric_readers=[PeriodicExportingMetricReader(OTLPMetricExporter())])
    )
    logger.info("OpenTelemetry export enabled (OTLP/HTTP)")
    return True
