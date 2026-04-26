import json
import logging

from fastapi import FastAPI

from axg.engine import DecisionEngine
from axg.models import DecisionRequest, DecisionResponse

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("uvicorn.error")

app = FastAPI(
    title="AXG - Agent Execution Guard",
    version="0.1.0",
    description="Deterministic execution control plane for AI agent actions.",
)

engine = DecisionEngine()


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "axg"}


@app.post("/v1/decisions", response_model=DecisionResponse)
def create_decision(request: DecisionRequest) -> DecisionResponse:
    logger.info(
        json.dumps(
            {
                "service": "axg",
                "component": "api",
                "event": "axg.decision.request_received",
                "flow": request.metadata.get("flow")
                or f"{request.source}:{request.action_type}",
                "execution_id": request.execution_id,
                "app_id": request.app_id,
                "plugin_id": request.plugin_id,
                "source": request.source,
                "action_type": request.action_type,
                "tenant_id": request.metadata.get("tenant_id"),
            },
            sort_keys=True,
        )
    )
    response = engine.decide(request)
    logger.info(
        json.dumps(
            {
                "service": "axg",
                "component": "api",
                "event": "axg.decision.response_emitted",
                "flow": request.metadata.get("flow")
                or f"{request.source}:{request.action_type}",
                "execution_id": response.execution_id,
                "decision": response.decision.value,
                "plugin_version": response.plugin_version,
                "tenant_id": request.metadata.get("tenant_id"),
            },
            sort_keys=True,
        )
    )
    return response
