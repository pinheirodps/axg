"""The examples referenced by the README and docs must keep working."""

import json
from pathlib import Path

import pytest

from axg.engine import DecisionEngine
from axg.models import Decision, DecisionRequest
from axg.plugin_loader import PluginLoader

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def _request(name: str) -> DecisionRequest:
    return DecisionRequest.model_validate_json((EXAMPLES / name).read_text(encoding="utf-8"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("example", "plugins", "decision"),
    [
        ("allow.json", ROOT / "plugins", Decision.ALLOW),
        ("block.json", ROOT / "plugins", Decision.BLOCK),
        ("refund_request.json", EXAMPLES / "plugins", Decision.CONFIRM),
    ],
)
async def test_documented_examples_decide_as_documented(example, plugins, decision):
    response = await DecisionEngine(loader=PluginLoader(plugins)).decide(_request(example))
    assert response.decision == decision


def test_example_policy_validates_against_the_published_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "schemas" / "plugin_manifest.v1.schema.json").read_text(encoding="utf-8"))
    policy = json.loads((EXAMPLES / "plugins" / "support_refunds" / "rules.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(policy)


def test_cli_example_request_is_a_valid_decision_request():
    assert _request("request.json").plugin_id == "finnorte"


REFUND = {
    "execution_id": "r", "tenant_id": "acme", "app_id": "support", "plugin_id": "support_refunds", "source": "api",
    "action_type": "issue_refund", "payload": {"amount": 80},
    "agent": {"id": "support-agent", "permissions": ["refunds:write"]}, "llm": {"confidence": 0.95},
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes", "decision"),
    [
        ({"action_type": "lookup_order", "payload": {"order_id": "A-1"}}, Decision.ALLOW),
        ({}, Decision.ALLOW),
        ({"payload": {"amount": 800}}, Decision.CONFIRM),
        ({"payload": {"amount": 80, "destination_added_in_session": True}}, Decision.BLOCK),
        ({"agent": {"id": "support-agent", "permissions": []}}, Decision.BLOCK),
        ({"source": "chat", "intent": {"original": "unknown", "resolved": "issue_refund"}}, Decision.CONFIRM),
        ({"action_type": "delete_customer"}, Decision.CONFIRM),
    ],
)
async def test_policy_guide_table(changes, decision):
    """Each row of the table in docs/policies.md."""
    request = DecisionRequest.model_validate({**REFUND, **changes})
    response = await DecisionEngine(loader=PluginLoader(EXAMPLES / "plugins")).decide(request)
    assert response.decision == decision
