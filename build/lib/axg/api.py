import json
import logging
import os
from typing import Annotated

from fastapi import FastAPI, BackgroundTasks, Header, HTTPException

from axg.engine import DecisionEngine
from axg.models import DecisionRequest, DecisionResponse
from axg.audit import audit_manager
from axg.crypto import get_public_key, get_jwks, key_manager

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("uvicorn.error")

app = FastAPI(
    title="AXG - Agent Execution Guard",
    version="0.1.0",
    description="Deterministic execution control plane for AI agent actions.",
)

engine = DecisionEngine()

@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "axg"}

@app.get("/v1/certs")
async def get_certs() -> dict[str, str]:
    """Exposes the public key for verifying AXG decision tokens (Legacy PEM)."""
    return {"public_key": get_public_key(), "kid": key_manager.KID, "alg": "RS256"}


@app.get("/.well-known/jwks.json")
async def get_jwks_endpoint():
    """Standard JWKS endpoint for automated key discovery."""
    return get_jwks()


@app.post("/v1/plugins/reload")
async def reload_plugins(authorization: Annotated[str | None, Header()] = None) -> dict[str, str]:
    """Clears the plugin cache to allow dynamic reloading of policies."""
    expected_token = os.environ.get("AXG_ADMIN_TOKEN")
    if not expected_token:
        raise HTTPException(status_code=401, detail="AXG_ADMIN_TOKEN is not configured")
    if not authorization or authorization != f"Bearer {expected_token}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Cache clear is sync, but route is async for consistency
    engine.loader._cache.clear()
    return {"status": "reloaded"}


@app.post("/v1/decisions", response_model=DecisionResponse)
async def create_decision(request: DecisionRequest, background_tasks: BackgroundTasks) -> DecisionResponse:
    """Core endpoint to evaluate agent actions against security policies."""
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
                "tenant_id": request.tenant_id,
            },
            sort_keys=True,
        )
    )
    
    # Engine is now async
    response = await engine.decide(request)
    
    # Audit recording is already async and handled in background
    decision_log = engine.get_decision_log(request, response)
    background_tasks.add_task(audit_manager.record_decision, decision_log)
    
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
                "tenant_id": request.tenant_id,
            },
            sort_keys=True,
        )
    )
    return response
