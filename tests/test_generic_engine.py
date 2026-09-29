"""A-08: the engine is domain-agnostic; uncertainty gating comes from each plugin's manifest."""

import json

import pytest

from axg.engine import DecisionEngine
from axg.models import Decision, DecisionRequest
from axg.plugin_loader import PluginLoader


def _loader(tmp_path, plugin_id, **manifest):
    folder = tmp_path / plugin_id
    folder.mkdir()
    data = {"plugin": plugin_id, "version": "1.0.0", "domain": "test", "rules": [], **manifest}
    (folder / "rules.json").write_text(json.dumps(data), encoding="utf-8")
    return PluginLoader(plugins_dir=tmp_path)


def _uncertain_request(plugin_id: str, action: str, **extra) -> DecisionRequest:
    return DecisionRequest(
        execution_id="exec_generic",
        tenant_id="t1",
        app_id="app",
        plugin_id=plugin_id,
        source="telegram_bot",
        action_type=action,
        llm={"confidence": 0.99},
        intent={"original": "unknown", "resolved": action},
        **extra,
    )


@pytest.mark.asyncio
async def test_plugin_without_gate_does_not_force_confirmation(tmp_path):
    engine = DecisionEngine(loader=_loader(tmp_path, "crm", actions={"create_expense": {"base_risk": 0.1}}))
    response = await engine.decide(_uncertain_request("crm", "create_expense"))
    assert response.decision == Decision.ALLOW
    assert "financial_write_requires_confirmation" not in response.audit_flags


@pytest.mark.asyncio
async def test_plugin_defines_its_own_gate(tmp_path):
    gate = {
        "actions": ["send_contract"],
        "uncertain_sources": ["email_bot"],
        "uncertain_source_suffixes": ["_bot"],
        "threshold": 0.5,
        "audit_flag": "legal_write_requires_confirmation",
        "reason": "Uncertain legal action: confirm first.",
    }
    engine = DecisionEngine(loader=_loader(tmp_path, "legal", uncertainty_gate=gate))

    gated = await engine.decide(_uncertain_request("legal", "send_contract"))
    assert gated.decision == Decision.CONFIRM
    assert "legal_write_requires_confirmation" in gated.audit_flags
    assert gated.reason == "Uncertain legal action: confirm first."

    other = await engine.decide(_uncertain_request("legal", "read_contract"))
    assert "legal_write_requires_confirmation" not in other.audit_flags


@pytest.mark.asyncio
async def test_finnorte_keeps_its_financial_gate():
    agent = {"id": "bot", "permissions": ["expense:create"]}
    response = await DecisionEngine().decide(_uncertain_request("finnorte", "create_expense", agent=agent))
    assert response.decision == Decision.CONFIRM
    assert "financial_write_requires_confirmation" in response.audit_flags
    assert "financial write operation" in response.reason


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("permissions", "expected"),
    [([], Decision.BLOCK), (["expense:create"], Decision.CONFIRM)],
)
async def test_uncertainty_gate_never_lowers_a_block(permissions, expected):
    """An uncertain write raises the decision to CONFIRM, but a missing permission still BLOCKs."""
    request = DecisionRequest(
        execution_id="gate-block", tenant_id="t", app_id="finnorte", plugin_id="finnorte",
        source="whatsapp_bot", action_type="create_expense", payload={"amount": 10},
        agent={"id": "bot", "permissions": permissions}, llm={"confidence": 0.95},
    )
    response = await DecisionEngine().decide(request)

    assert response.decision == expected
    if expected == Decision.BLOCK:
        assert response.reason == "The proposed action is not permitted for this agent."
