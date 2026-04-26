from fastapi import FastAPI

from axg.engine import DecisionEngine
from axg.models import DecisionRequest, DecisionResponse


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
    return engine.decide(request)

