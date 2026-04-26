import json
from io import StringIO

import pytest
from fastapi.testclient import TestClient

from axg.api import app
from axg.engine import DecisionEngine
from axg.models import (
    ConditionGroup,
    Decision,
    DecisionRequest,
    Plugin,
    PolicyRule,
    RuleCondition,
)
from axg.plugin_loader import PluginLoadError, PluginLoader
from axg.rules import RuleEngine


def request_data(**overrides):
    data = {
        "execution_id": "exec_001",
        "app_id": "finnorte",
        "plugin_id": "finnorte",
        "user_id": "test_user_001",
        "agent": {
            "id": "muai_whatsapp",
            "type": "service",
            "permissions": [
                "expense:create",
                "transaction:categorize",
                "subscription:detect",
            ],
        },
        "source": "whatsapp",
        "action_type": "create_expense",
        "payload": {
            "merchant": "Uber",
            "amount": 15,
            "currency": "EUR",
            "proposed_action": "create_expense",
            "proposed_category": "Transport",
            "merchant_type": "transport",
        },
        "context": {
            "merchant_history_count": 12,
            "recurrence_pattern": False,
        },
        "llm": {
            "model": "llama-3.3-70b",
            "confidence": 0.91,
            "raw_output": {},
        },
        "metadata": {
            "tenant_id": "tenant_001",
        },
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key].update(value)
        else:
            data[key] = value
    return data


def make_request(**overrides):
    return DecisionRequest.model_validate(request_data(**overrides))


class MissingPath:
    def __truediv__(self, _value):
        return self

    def exists(self):
        return False


class FilePath:
    def __init__(self, content):
        self.content = content

    def __truediv__(self, _value):
        return self

    def exists(self):
        return True

    def open(self, *_args, **_kwargs):
        return StringIO(self.content)


class StaticLoader:
    def __init__(self, plugin):
        self.plugin = plugin

    def load(self, _plugin_id):
        return self.plugin


def plugin_from_rules(rules, actions=None):
    return Plugin.model_validate(
        {
            "plugin": "test",
            "version": "0.1.0",
            "domain": "test",
            "actions": actions
            or {"create_expense": {"required_permissions": [], "base_risk": 0.2}},
            "rules": rules,
        }
    )


def test_plugin_loader_loads_finnorte_plugin():
    plugin = PluginLoader().load("finnorte")

    assert plugin.version_label == "finnorte@0.1.0"
    assert plugin.actions["create_expense"].base_risk == 0.45


def test_plugin_loader_missing_invalid_json_and_invalid_schema():
    with pytest.raises(PluginLoadError):
        PluginLoader(MissingPath()).load("missing")
    with pytest.raises(PluginLoadError):
        PluginLoader(FilePath("{bad-json")).load("broken")
    with pytest.raises(PluginLoadError):
        PluginLoader(FilePath(json.dumps({"plugin": "broken"}))).load("broken")


def test_condition_group_requires_condition():
    with pytest.raises(ValueError):
        ConditionGroup()


@pytest.mark.parametrize(
    ("operator", "actual", "expected"),
    [
        ("eq", "transport", "transport"),
        ("neq", "transport", "food"),
        ("gt", 10, 5),
        ("gte", 10, 10),
        ("lt", 3, 5),
        ("lte", 3, 3),
        ("in", "whatsapp", ["whatsapp", "telegram"]),
        ("not_in", "bank_sync", ["whatsapp", "telegram"]),
        ("exists", "Uber", None),
        ("contains", "Uber Portugal", "uber"),
    ],
)
def test_rule_engine_supported_operators(operator, actual, expected):
    condition = RuleCondition(field="payload.value", operator=operator, value=expected)

    assert RuleEngine().evaluate_condition(condition, {"payload": {"value": actual}})


def test_rule_engine_any_all_missing_invalid_and_contains_list():
    engine = RuleEngine()
    group = ConditionGroup(
        all=[RuleCondition(field="payload.amount", operator="gt", value=10)],
        any=[
            RuleCondition(field="source", operator="eq", value="telegram"),
            RuleCondition(field="source", operator="eq", value="whatsapp"),
        ],
    )

    assert engine.evaluate_group(
        group, {"payload": {"amount": 15}, "source": "whatsapp"}
    )
    assert not engine.evaluate_condition(
        RuleCondition(field="payload.missing", operator="eq", value=1),
        {"payload": {}},
    )
    assert not engine.evaluate_condition(
        RuleCondition(field="payload.amount", operator="gt", value=1),
        {"payload": {"amount": "not-a-number"}},
    )
    assert not engine.evaluate_condition(
        RuleCondition(field="payload.amount", operator="contains", value="uber"),
        {"payload": {"amount": 15}},
    )
    assert not engine.evaluate_condition(
        RuleCondition(field="payload.amount", operator="eval", value="unsafe"),
        {"payload": {"amount": 15}},
    )
    assert engine.evaluate_condition(
        RuleCondition(field="payload.tags", operator="contains", value="uber"),
        {"payload": {"tags": ["uber"]}},
    )
    engine.supported_operators = {*RuleEngine.supported_operators, "future"}
    assert not engine.evaluate_condition(
        RuleCondition(field="payload.amount", operator="future", value=15),
        {"payload": {"amount": 15}},
    )


def test_uber_1500_whatsapp_requires_confirmation():
    response = DecisionEngine().decide(
        make_request(
            payload={"merchant": "Uber", "amount": 1500},
            llm={"confidence": 0.78},
        )
    )

    assert response.decision == Decision.CONFIRM
    assert "high_value_transaction" in response.audit_flags
    assert "merchant_amount_anomaly" in response.audit_flags
    assert "significantly higher" in response.human_readable_reason
    assert response.scores.risk_score == 0.9
    assert response.scores.final_confidence == 0.48


def test_decision_log_is_structured_for_flow_debugging(caplog):
    caplog.set_level("INFO", logger="axg.engine")

    response = DecisionEngine().decide(
        make_request(
            execution_id="test_exec_uber_1500_001",
            metadata={
                "tenant_id": "test_tenant_001",
                "flow": "bot_expense_validation",
                "situation": "uber_high_value_expense",
            },
            payload={"merchant": "Uber", "amount": 1500},
        )
    )

    logged = [
        json.loads(record.message)
        for record in caplog.records
        if "axg.decision.evaluated" in record.message
    ][0]
    assert response.decision == Decision.CONFIRM
    assert logged["service"] == "axg"
    assert logged["flow"] == "bot_expense_validation"
    assert logged["situation"] == "uber_high_value_expense"
    assert logged["execution_id"] == "test_exec_uber_1500_001"
    assert logged["decision"] == "CONFIRM"
    assert logged["audit_flags"] == [
        "high_value_transaction",
        "requires_user_confirmation",
        "merchant_amount_anomaly",
    ]


def test_poc_uber_1500_contract_without_agent_requires_confirmation():
    data = request_data(
        execution_id="test_exec_uber_1500_001",
        source="whatsapp",
        payload={
            "merchant": "Uber",
            "amount": 1500,
            "currency": "EUR",
            "category": "Transport",
            "description": "Uber",
            "proposed_action": "create_expense",
        },
        context={
            "merchant_history_count": 5,
            "merchant_average_amount": 18.5,
            "category_average_amount": 22.0,
            "user_average_expense_amount": 31.0,
            "is_known_merchant": True,
            "is_recurring": False,
        },
        llm={"model": "llama-3.3-70b", "confidence": 0.75, "raw_output": {}},
        metadata={
            "tenant_id": "test_tenant_001",
            "channel": "whatsapp",
            "environment": "production-validation",
        },
    )
    data.pop("agent")

    response = DecisionEngine().decide(DecisionRequest.model_validate(data))

    assert response.decision == Decision.CONFIRM
    assert response.scores.llm_confidence == 0.75
    assert response.scores.final_confidence == 0.45
    assert response.scores.risk_score == 0.9
    assert response.actionable_payload["merchant"] == "Uber"
    assert response.actionable_payload["amount"] == 1500
    assert response.actionable_payload["category"] == "Transport"
    assert response.audit_flags == [
        "high_value_transaction",
        "requires_user_confirmation",
        "merchant_amount_anomaly",
    ]
    assert [rule.id for rule in response.rules_triggered] == [
        "high_value_transaction",
        "merchant_amount_anomaly",
    ]


def test_poc_honorato_restaurant_subscription_is_not_allowed():
    data = request_data(
        execution_id="test_exec_honorato_subscription_001",
        source="bank_sync",
        action_type="categorize_transaction",
        payload={
            "transaction_id": "txn_honorato_001",
            "merchant": "HONORATO PIZZA",
            "amount": 19.5,
            "currency": "EUR",
            "proposed_category": "Subscription",
            "proposed_action": "detect_subscription",
            "is_subscription": True,
            "merchant_type": "restaurant",
        },
        context={
            "merchant_history_count": 1,
            "merchant_average_amount": 22.0,
            "category_average_amount": 25.0,
            "recurrence_pattern": False,
            "amount_variance_percent": 35,
            "is_known_merchant": False,
            "previous_user_confirmed_category": None,
        },
        llm={"model": "llama-3.3-70b", "confidence": 0.87, "raw_output": {}},
        metadata={
            "tenant_id": "test_tenant_001",
            "environment": "production-validation",
        },
    )
    data.pop("agent")

    response = DecisionEngine().decide(DecisionRequest.model_validate(data))

    assert response.decision in (Decision.SUGGEST, Decision.CONFIRM)
    assert response.decision != Decision.ALLOW
    assert response.actionable_payload["transaction_id"] == "txn_honorato_001"
    assert response.actionable_payload["suggested_category"] == "Food & Dining"
    assert response.actionable_payload["is_subscription"] is False
    assert "merchant_type_incompatible_with_subscription" in response.audit_flags
    assert "missing_recurrence_pattern" in response.audit_flags


def test_poc_recurring_condominium_subscription_is_allowed():
    data = request_data(
        execution_id="test_exec_condominium_001",
        source="bank_sync",
        action_type="categorize_transaction",
        payload={
            "transaction_id": "txn_condominium_001",
            "merchant": "TRF CRED SEPA+ App 645464129 P/ Condominio",
            "amount": 65.0,
            "currency": "EUR",
            "proposed_category": "Housing",
            "proposed_action": "detect_subscription",
            "is_subscription": True,
            "merchant_type": "housing",
        },
        context={
            "merchant_history_count": 6,
            "recurrence_pattern": True,
            "recurrence_interval_days": 30,
            "amount_variance_percent": 2,
            "previous_user_confirmed_category": "Housing",
        },
        llm={"model": "llama-3.3-70b", "confidence": 0.93, "raw_output": {}},
    )
    data.pop("agent")

    response = DecisionEngine().decide(DecisionRequest.model_validate(data))

    assert response.decision == Decision.ALLOW
    assert response.actionable_payload["suggested_category"] == "Housing"
    assert response.actionable_payload["is_subscription"] is True


def test_normal_uber_can_be_allowed():
    response = DecisionEngine().decide(make_request())

    assert response.decision == Decision.ALLOW
    assert response.rules_triggered == []


def test_low_confidence_without_rule_becomes_suggest_or_confirm():
    suggest = DecisionEngine().decide(make_request(llm={"confidence": 0.7}))
    confirm = DecisionEngine().decide(make_request(llm={"confidence": 0.5}))

    assert suggest.decision == Decision.SUGGEST
    assert confirm.decision == Decision.CONFIRM
    assert "low_confidence" in confirm.audit_flags


def test_missing_permission_blocks():
    engine = DecisionEngine(
        loader=StaticLoader(
            plugin_from_rules(
                [],
                actions={
                    "create_expense": {
                        "required_permissions": ["expense:create"],
                        "base_risk": 0.2,
                    }
                },
            )
        )
    )

    response = engine.decide(
        make_request(
            plugin_id="test", agent={"id": "agent_without_access", "permissions": []}
        )
    )
    assert response.decision == Decision.BLOCK
    assert (
        response.human_readable_reason
        == "The proposed action is not permitted for this agent."
    )


def test_missing_agent_blocks_when_permission_is_required():
    engine = DecisionEngine(
        loader=StaticLoader(
            plugin_from_rules(
                [],
                actions={
                    "create_expense": {
                        "required_permissions": ["expense:create"],
                        "base_risk": 0.2,
                    }
                },
            )
        )
    )
    data = request_data(plugin_id="test")
    data.pop("agent")

    response = engine.decide(DecisionRequest.model_validate(data))

    assert response.decision == Decision.BLOCK


def test_unknown_action_confirms_with_default_risk():
    response = DecisionEngine().decide(make_request(action_type="unknown_action"))

    assert response.decision == Decision.CONFIRM
    assert response.scores.risk_score == 0.7


def test_low_confidence_without_matching_rules_confirms():
    engine = DecisionEngine(loader=StaticLoader(plugin_from_rules([])))

    response = engine.decide(make_request(plugin_id="test", llm={"confidence": 0.5}))

    assert response.decision == Decision.CONFIRM
    assert (
        response.human_readable_reason
        == "The proposal requires confirmation before execution."
    )


def test_decision_precedence_block_wins():
    rules = [
        {
            "id": "confirm_rule",
            "description": "confirm",
            "condition": {
                "all": [{"field": "payload.amount", "operator": "gt", "value": 1}]
            },
            "decision": "CONFIRM",
            "reason": "confirm",
        },
        {
            "id": "block_rule",
            "description": "block",
            "condition": {
                "all": [{"field": "payload.amount", "operator": "gt", "value": 1}]
            },
            "decision": "BLOCK",
            "reason": "block",
        },
    ]
    engine = DecisionEngine(loader=StaticLoader(plugin_from_rules(rules)))

    assert engine.decide(make_request(plugin_id="test")).decision == Decision.BLOCK


def test_default_penalty_and_rule_actionable_payload():
    rule = PolicyRule(
        id="confirm_with_default_penalty",
        description="confirm",
        condition=ConditionGroup(
            all=[RuleCondition(field="payload.amount", operator="gt", value=1)]
        ),
        decision=Decision.CONFIRM,
        reason="confirm",
        actionable_payload={"safe": True},
    )
    engine = DecisionEngine(loader=StaticLoader(plugin_from_rules([rule.model_dump()])))
    response = engine.decide(make_request(plugin_id="test"))

    assert response.scores.final_confidence == 0.66
    assert response.actionable_payload["safe"] is True


def test_fail_safe_on_plugin_failure():
    response = DecisionEngine(loader=PluginLoader(MissingPath())).decide(make_request())

    assert response.decision == Decision.CONFIRM
    assert response.scores.risk_score == 1.0
    assert response.audit_flags == ["plugin_load_failed"]


def test_api_health_and_decision_endpoint():
    client = TestClient(app)

    assert client.get("/health").json() == {"status": "ok", "service": "axg"}

    response = client.post("/v1/decisions", json=request_data(payload={"amount": 1500}))

    assert response.status_code == 200
    assert response.json()["decision"] == "CONFIRM"


def test_api_logs_decision_request(caplog):
    caplog.set_level("INFO", logger="axg.api")
    client = TestClient(app)

    response = client.post(
        "/v1/decisions",
        json=request_data(
            execution_id="test_exec_api_log",
            metadata={"tenant_id": "tenant_001", "flow": "bank_sync_categorization"},
        ),
    )

    logged = [
        json.loads(record.message)
        for record in caplog.records
        if "axg.decision.request_received" in record.message
    ][0]
    assert response.status_code == 200
    assert logged["service"] == "axg"
    assert logged["component"] == "api"
    assert logged["flow"] == "bank_sync_categorization"
    assert logged["execution_id"] == "test_exec_api_log"
