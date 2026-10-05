"""budget_guard: the policy MUAI asks before reserving AI credits (reserve_ai_credits)."""

import pytest

from axg.engine import DecisionEngine
from axg.models import Decision, DecisionRequest


def _request(balance=1000, cost=0.01, points=10):
    # The request MUAI's LLM gateway sends (backend/app/core/llm/__init__.py)
    return DecisionRequest(
        schema_version="axg_budget_decision_request.v1",
        execution_id="exec-1",
        tenant_id="social",
        app_id="social",
        plugin_id="budget_guard",
        user_id="system",
        source="muai_llm_gateway",
        action_type="reserve_ai_credits",
        payload={"workflow_id": "exec-1", "estimated_points": points, "estimated_cost_usd": cost,
                 "provider": "groq", "model": "llama-3.3-70b-versatile"},
        context={"current_balance": balance},
        llm={"model": "default", "confidence": 1.0},
    )


@pytest.mark.asyncio
async def test_an_ordinary_call_is_allowed():
    response = await DecisionEngine().decide(_request())
    assert response.decision == Decision.ALLOW
    assert "plugin_load_failed" not in response.audit_flags


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("request_kwargs", "flag"),
    [
        ({"balance": 0}, "budget_no_balance"),
        ({"balance": -5}, "budget_no_balance"),
        ({"cost": 2.5}, "budget_single_call_ceiling"),
    ],
)
async def test_spend_outside_the_budget_is_blocked(request_kwargs, flag):
    response = await DecisionEngine().decide(_request(**request_kwargs))
    assert response.decision == Decision.BLOCK and flag in response.audit_flags


@pytest.mark.asyncio
async def test_a_call_at_the_ceiling_is_allowed():
    assert (await DecisionEngine().decide(_request(cost=2.0))).decision == Decision.ALLOW
