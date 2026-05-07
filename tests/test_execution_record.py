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
    
    assert record.execution_id == "exec_123"
    assert record.tenant_id == "tenant_abc"
    assert record.requested_by == "user_456"
    assert record.muai_action_type == "add_expense"
    assert record.axg_decision == Decision.CONFIRM
    assert record.execution_status == ExecutionStatus.PENDING
    assert record.input_hash is not None
    assert len(record.input_hash) == 64 # SHA-256

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
