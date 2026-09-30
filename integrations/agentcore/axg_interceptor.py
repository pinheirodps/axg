"""AWS Bedrock AgentCore Gateway REQUEST interceptor that asks AXG before every MCP tool call.

Deploy as the gateway's REQUEST interceptor (Lambda, Python 3.12, standard library only) with
``passRequestHeaders: true``. It runs **before** the gateway's Cedar policy:

- ``tools/call`` becomes an AXG decision for the calling agent;
- ALLOW: the call continues with the AXG Passport and the actionable payload in ``params._meta``,
  so the tool can verify the exact call it is executing;
- SUGGEST / CONFIRM / BLOCK, or AXG unavailable: the tool is not called. The agent receives a
  tool result with ``isError: true`` and the reason, so it can ask the user to confirm (fail closed).
  For SUGGEST / CONFIRM the result's ``_meta["io.axg/approval"]`` carries AXG's approval ticket and
  the payload, for the host application to run the approval flow (docs/approvals.md);
- a ``tools/call`` that already carries a Passport (e.g. after a human approval) is checked with AXG's
  Passport introspection instead of a new decision, and passes unchanged when valid;
- every other MCP method passes through unchanged.

Configuration (environment variables):
  AXG_URL            base URL of AXG, e.g. https://axg.internal:8090           (required)
  AXG_API_KEY        this interceptor's key in AXG_CLIENTS                     (required)
  AXG_APP_ID         Passport audience: the app/system behind the gateway      (required)
  AXG_PLUGIN_ID      AXG policy plugin for these tools                         (default: AXG_APP_ID)
  AXG_TENANT_CLAIM   JWT claim holding the tenant                              (default: tenant_id)
  AXG_AGENT_CLAIM    JWT claim identifying the agent                           (default: client_id, then sub)
  AXG_TIMEOUT_SECONDS                                                          (default: 3)
  AXG_CEDAR_CONTEXT  "true" to add arguments.axg = {decision, risk_level} for Cedar policies (default: off)

The caller's JWT was already validated by the gateway's inbound authorizer; its claims are read here
(not re-verified) to identify tenant and agent. OAuth scopes become the agent's AXG permissions,
still capped by this interceptor's permission ceiling in AXG_CLIENTS.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.error
import urllib.request
import uuid
from typing import Any

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PASSPORT_META_KEY = "io.axg/passport"
PAYLOAD_META_KEY = "io.axg/actionable_payload"
DECISION_META_KEY = "io.axg/decision"
APPROVAL_META_KEY = "io.axg/approval"


class AxgUnavailable(Exception):
    pass


def _jwt_claims(headers: dict[str, str]) -> dict[str, Any]:
    """Claims of the (gateway-validated) bearer token; empty when absent or unreadable."""
    auth = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return {}


def build_decision_request(body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    params = body.get("params") or {}
    claims = _jwt_claims(headers)
    app_id = os.environ["AXG_APP_ID"]
    agent_id = claims.get(os.environ.get("AXG_AGENT_CLAIM", "client_id")) or claims.get("sub") or "unknown-agent"
    scopes = claims.get("scope", "")
    permissions = scopes.split() if isinstance(scopes, str) else list(scopes)
    return {
        "execution_id": f"agentcore-{body.get('id', '')}-{uuid.uuid4()}",
        "tenant_id": str(claims.get(os.environ.get("AXG_TENANT_CLAIM", "tenant_id")) or "default"),
        "app_id": app_id,
        "plugin_id": os.environ.get("AXG_PLUGIN_ID", app_id),
        "user_id": claims.get("sub"),
        "agent": {"id": str(agent_id), "type": "agent", "permissions": permissions},
        "source": "agentcore",
        "action_type": params.get("name", ""),
        "payload": params.get("arguments") or {},
        # An explicit tool call is not an LLM guess: policy rules and permissions decide
        "llm": {"confidence": 1.0},
        "metadata": {"flow": "agentcore:tools/call"},
    }


def _post_axg(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{os.environ['AXG_URL'].rstrip('/')}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {os.environ['AXG_API_KEY']}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=float(os.environ.get("AXG_TIMEOUT_SECONDS", "3"))) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise AxgUnavailable(str(exc)) from exc


def ask_axg(decision_request: dict[str, Any]) -> dict[str, Any]:
    return _post_axg("/v1/decisions", decision_request)


def introspect_passport(passport: str, tool: str, authorized: dict[str, Any]) -> dict[str, Any]:
    """Ask AXG whether a Passport is valid for this tool and payload (RS256 cannot be checked with the stdlib)."""
    return _post_axg("/v1/passports/introspect", {"passport": passport, "action_type": tool, "actionable_payload": authorized})


def _arguments_authorized(arguments: dict[str, Any], authorized: dict[str, Any]) -> bool:
    """Every argument must appear, unchanged, in the payload the Passport authorizes."""
    return all(key in authorized and authorized[key] == value for key, value in arguments.items() if key != "axg")


def _approved_call(body: dict[str, Any], params: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    """A call that already carries a Passport (for example after a human approval): check it instead of deciding again.

    AXG is stateless, so single use is enforced where the Passport is consumed: the MCP tool verifies it with a
    replay cache, as it does for every AXG-authorized call.
    """
    authorized = meta.get(PAYLOAD_META_KEY)
    if not isinstance(authorized, dict) or not _arguments_authorized(params.get("arguments") or {}, authorized):
        return _tool_error(body, "Blocked: the arguments differ from what the Passport authorizes.", {"decision": "INVALID_PASSPORT"})
    try:
        result = introspect_passport(meta[PASSPORT_META_KEY], params.get("name") or "", authorized)
    except AxgUnavailable as exc:
        logger.error("AXG unavailable, refusing Passport-carrying call %s: %s", params.get("name"), exc)
        return _tool_error(
            body, "This action could not be authorized right now (governance service unavailable). Try again later.",
            {"decision": "UNAVAILABLE"},
        )
    if not result.get("active"):
        reason = result.get("reason") or "the Passport is not valid for this call"
        return _tool_error(body, f"Blocked: {reason}.", {"decision": "INVALID_PASSPORT"})
    logger.info(json.dumps({"event": "axg.agentcore.passport_accepted", "tool": params.get("name"),
                            "jti": (result.get("claims") or {}).get("jti")}))
    return _pass_through(body)


def _tool_error(
    body: dict[str, Any], text: str, axg: dict[str, Any], approval: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Short-circuit the call with a tool result the agent can read (isError), not a protocol error.

    An approval goes in the result's _meta (host metadata), not in the content the model reads.
    """
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"axg": axg},
        "isError": True,
    }
    if approval:
        result["_meta"] = {APPROVAL_META_KEY: approval}
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 200,
                "body": {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "result": result,
                },
            }
        },
    }


def _pass_through(body: dict[str, Any]) -> dict[str, Any]:
    return {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": body}}}


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    gateway_request = (event.get("mcp") or {}).get("gatewayRequest") or {}
    body = gateway_request.get("body") or {}
    if body.get("method") != "tools/call":
        return _pass_through(body)

    params = body.get("params") or {}
    meta = params.get("_meta") or {}
    if meta.get(PASSPORT_META_KEY):
        return _approved_call(body, params, meta)

    decision_request = build_decision_request(body, gateway_request.get("headers") or {})
    try:
        decision = ask_axg(decision_request)
    except AxgUnavailable as exc:
        logger.error("AXG unavailable, refusing tool call %s: %s", decision_request["action_type"], exc)
        return _tool_error(
            body,
            "This action could not be authorized right now (governance service unavailable). Try again later.",
            {"decision": "UNAVAILABLE", "execution_id": decision_request["execution_id"]},
        )

    verdict = decision.get("decision")
    summary = {
        "decision": verdict,
        "execution_id": decision.get("execution_id"),
        "reason": decision.get("reason"),
        "risk_level": (decision.get("scores") or {}).get("risk_level"),
    }
    logger.info(json.dumps({"event": "axg.agentcore.decision", "tool": decision_request["action_type"], **summary}))

    if verdict != "ALLOW" or not decision.get("passport"):
        prefix = "Blocked by policy" if verdict == "BLOCK" else "Confirmation required"
        approval = decision.get("approval")
        if approval:
            approval = {**approval, "actionable_payload": decision.get("actionable_payload") or {}}
        return _tool_error(body, f"{prefix}: {decision.get('reason') or 'no reason given'}", summary, approval)

    params = dict(body.get("params") or {})
    params["_meta"] = {
        **(params.get("_meta") or {}),
        PASSPORT_META_KEY: decision["passport"],
        PAYLOAD_META_KEY: decision.get("actionable_payload") or {},
        DECISION_META_KEY: summary,
    }
    if os.environ.get("AXG_CEDAR_CONTEXT", "").lower() == "true":
        params["arguments"] = {
            **(params.get("arguments") or {}),
            "axg": {"decision": verdict, "risk_level": summary["risk_level"]},
        }
    return _pass_through({**body, "params": params})
