import hmac
import json
import logging
import os
from typing import Annotated

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request

from axg.auth import ANONYMOUS, Caller, authenticate, auth_mode
from axg.engine import DecisionEngine
from axg.models import DecisionRequest, DecisionResponse
from axg.audit import audit_manager
from axg.crypto import get_public_key, get_jwks, key_manager
from axg.limits import BodySizeLimitMiddleware, rate_limiter
from axg.telemetry import AXG_VERSION, configure_from_env, continue_trace

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("uvicorn.error")
configure_from_env()

app = FastAPI(
    title="AXG - Agent Execution Guard",
    version=AXG_VERSION,
    description="Deterministic execution control plane for AI agent actions.",
)
app.add_middleware(BodySizeLimitMiddleware)

engine = DecisionEngine()

@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "axg"}

@app.get("/v1/certs")
async def get_certs() -> dict[str, str]:
    """Exposes the public key for verifying AXG decision tokens (Legacy PEM)."""
    return {"public_key": get_public_key(), "kid": key_manager.kid, "alg": "RS256"}


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
    if not authorization or not hmac.compare_digest(authorization, f"Bearer {expected_token}"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    engine.loader.clear_cache()
    return {"status": "reloaded"}


def resolve_caller(authorization: Annotated[str | None, Header()] = None) -> Caller:
    """Identify the network caller from its API key (``Authorization: Bearer <key>``)."""
    if authorization:
        scheme, _, api_key = authorization.partition(" ")
        caller = authenticate(api_key.strip()) if scheme.lower() == "bearer" and api_key.strip() else None
        if caller is None:
            raise HTTPException(status_code=401, detail="Invalid API key", headers={"WWW-Authenticate": "Bearer"})
        return caller
    if auth_mode() == "optional":
        return ANONYMOUS
    raise HTTPException(status_code=401, detail="API key required", headers={"WWW-Authenticate": "Bearer"})


@app.post("/v1/decisions", response_model=DecisionResponse)
async def create_decision(
    request: DecisionRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    caller: Annotated[Caller, Depends(resolve_caller)],
) -> DecisionResponse:
    """Core endpoint to evaluate agent actions against security policies."""
    if not caller.may_act_for(request.app_id):
        raise HTTPException(status_code=403, detail="Caller is not allowed to request decisions for this app")
    retry_after = rate_limiter.check(caller.client_id)
    if retry_after is not None:
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": str(retry_after)})

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
                "client_id": caller.client_id,
            },
            sort_keys=True,
        )
    )

    with continue_trace(http_request.headers):
        response = await engine.decide(request, caller)
        # Audit recording using the ExecutionRecord spine, linked to the caller's trace
        execution_record = engine.get_execution_record(request, response)
    background_tasks.add_task(audit_manager.record_decision, execution_record)
    
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
