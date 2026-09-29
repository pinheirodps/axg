import pytest
from axg.models import DecisionRequest, LlmSignal, AgentIdentity, Decision, ExecutionStatus
from axg.engine import DecisionEngine

@pytest.mark.anyio
async def test_execution_record_generation():
    engine = DecisionEngine()
    
    request = DecisionRequest(
        execution_id="exec_123",
        tenant_id="tenant_abc",
        app_id="app_xyz",
        plugin_id="finnorte",
        source="whatsapp_bot",
        action_type="add_expense",
        payload={"amount": 100, "description": "Coffee"},
        user_id="user_456",
        llm=LlmSignal(confidence=0.9)
    )
    
    response = await engine.decide(request)
    record = engine.get_execution_record(request, response)
    
    assert record.schema_version == "axg.execution_record.v2"
    assert record.execution_id == "exec_123"
    assert record.tenant_id == "tenant_abc"
    assert record.plugin_id == "finnorte"
    assert record.requested_by == "user_456"
    assert record.agent_id is None
    assert record.action_type == "add_expense"
    assert record.proposal_confidence == 0.9
    # No agent: finnorte writes require a permission, so the uncertain write is still blocked
    assert record.decision == Decision.BLOCK
    assert record.policy == response.plugin_version
    assert record.risk_score == response.scores.risk_score
    assert record.execution_status == ExecutionStatus.PENDING
    assert record.input_hash is not None
    assert len(record.input_hash) == 64 # SHA-256
    assert record.created_at.endswith("+00:00")


@pytest.mark.anyio
async def test_execution_record_is_framework_neutral():
    """No field names any particular orchestrator: AXG stands alone."""
    request = DecisionRequest(
        execution_id="exec_neutral", tenant_id="t", app_id="a", plugin_id="finnorte", source="api",
        action_type="add_expense", payload={"amount": 1},
        agent=AgentIdentity(id="agent_9"), llm=LlmSignal(model="any-model", confidence=0.5),
        intent={"fallback_used": True},
    )
    engine = DecisionEngine()
    record = engine.get_execution_record(request, await engine.decide(request))

    assert record.agent_id == "agent_9"
    assert record.proposal_model == "any-model"
    assert record.intent_fallback_used is True
    assert not [field for field in record.model_dump() if "muai" in field or field.startswith("axg_")]

@pytest.mark.anyio
async def test_execution_record_requested_by_agent():
    engine = DecisionEngine()
    
    request = DecisionRequest(
        execution_id="exec_124",
        tenant_id="tenant_abc",
        app_id="app_xyz",
        plugin_id="finnorte",
        source="dashboard",
        action_type="add_expense",
        payload={"amount": 50},
        agent=AgentIdentity(id="agent_007", permissions=["financial_write"]),
        llm=LlmSignal(confidence=0.95)
    )
    
    response = await engine.decide(request)
    record = engine.get_execution_record(request, response)
    
    assert record.requested_by == "agent_007"

@pytest.mark.anyio
async def test_execution_record_rules_triggered():
    engine = DecisionEngine()
    
    # Trigger a rule (e.g. amount too high if we had such rule, but let's just check the list is populated if rules fire)
    # For now, let's just verify the field exists and is a list
    request = DecisionRequest(
        execution_id="exec_125",
        tenant_id="tenant_abc",
        app_id="app_xyz",
        plugin_id="finnorte",
        source="dashboard",
        action_type="add_expense",
        payload={"amount": 10},
        user_id="user_1",
        llm=LlmSignal(confidence=0.95)
    )
    
    response = await engine.decide(request)
    record = engine.get_execution_record(request, response)
    
    assert isinstance(record.rules_triggered, list)

@pytest.mark.anyio
async def test_execution_record_shadow_mode():
    engine = DecisionEngine()
    
    request = DecisionRequest(
        execution_id="exec_126",
        tenant_id="tenant_abc",
        app_id="app_xyz",
        plugin_id="finnorte",
        source="whatsapp_bot",
        action_type="add_expense",
        payload={"amount": 100},
        user_id="user_1",
        llm=LlmSignal(confidence=0.9),
        shadow_mode=True
    )
    
    response = await engine.decide(request)
    record = engine.get_execution_record(request, response)
    
    assert record.shadow_mode is True
    assert response.shadow_mode is True
    assert "shadow_mode_active" in record.audit_flags
