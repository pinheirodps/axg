import json
import pytest
import runpy
from axg.cli import cmd_validate_plugin, cmd_simulate_decision, get_parser, main
import argparse

def test_parser_validate():
    parser = get_parser()
    args = parser.parse_args(["validate-plugin", "--id", "finnorte"])
    assert args.command == "validate-plugin"
    assert args.id == "finnorte"

def test_parser_simulate():
    parser = get_parser()
    args = parser.parse_args(["simulate-decision", "--plugin", "finnorte", "--payload", "test.json"])
    assert args.command == "simulate-decision"
    assert args.plugin == "finnorte"
    assert args.payload == "test.json"

def test_cmd_validate_plugin_success(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "plugins" / "test_plugin"
    plugin_dir.mkdir(parents=True)
    
    (plugin_dir / "rules.json").write_text(json.dumps({
        "plugin": "test_plugin",
        "version": "1.0.0",
        "domain": "test",
        "actions": {"create": {"required_permissions": [], "base_risk": 0.1}},
        "rules": [
            {
                "id": "1",
                "description": "test",
                "condition": {"all": [{"field": "a", "operator": "eq", "value": "b"}]},
                "decision": "ALLOW",
                "reason": "because"
            }
        ]
    }))
    
    args = argparse.Namespace(command="validate-plugin", id="test_plugin", dir=str(tmp_path / "plugins"))
    assert cmd_validate_plugin(args) == 0

def test_cmd_validate_plugin_failure(tmp_path):
    args = argparse.Namespace(command="validate-plugin", id="missing_plugin", dir=str(tmp_path / 'plugins'))
    assert cmd_validate_plugin(args) == 1

def test_cmd_simulate_decision_success(tmp_path):
    plugin_dir = tmp_path / "plugins" / "test_plugin"
    plugin_dir.mkdir(parents=True)
    
    (plugin_dir / "rules.json").write_text(json.dumps({
        "plugin": "test_plugin",
        "version": "1.0.0",
        "domain": "test",
        "actions": {"create": {"required_permissions": [], "base_risk": 0.1}},
        "rules": [
            {
                "id": "1",
                "description": "test",
                "condition": {"all": [{"field": "payload.merchant", "operator": "eq", "value": "Uber"}]},
                "decision": "ALLOW",
                "reason": "because"
            }
        ]
    }))
    
    payload_file = tmp_path / "request.json"
    payload_file.write_text(json.dumps({
        "schema_version": "axg.decision_request.v1",
        "execution_id": "123",
        "tenant_id": "tenant_001",
        "app_id": "app",
        "user_id": "user",
        "source": "api",
        "action_type": "create",
        "payload": {"merchant": "Uber"}
    }))
    
    args = argparse.Namespace(command="simulate-decision", plugin="test_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'))
    assert cmd_simulate_decision(args) == 0

def test_cmd_simulate_decision_missing_payload(tmp_path):
    args = argparse.Namespace(command="simulate-decision", plugin="test", payload="missing.json", dir=str(tmp_path / 'plugins'))
    assert cmd_simulate_decision(args) == 1

def test_cmd_simulate_decision_plugin_load_error(tmp_path):
    payload_file = tmp_path / "request.json"
    payload_file.write_text("{}")
    
    args = argparse.Namespace(command="simulate-decision", plugin="missing_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'))
    assert cmd_simulate_decision(args) == 1

def test_cmd_simulate_decision_invalid_json(tmp_path):
    plugin_dir = tmp_path / "plugins" / "test_plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "rules.json").write_text(json.dumps({
        "plugin": "test_plugin",
        "version": "1.0.0",
        "domain": "test",
        "actions": {},
        "rules": []
    }))
    
    payload_file = tmp_path / "request.json"
    payload_file.write_text("{bad json")
    
    args = argparse.Namespace(command="simulate-decision", plugin="test_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'))
    assert cmd_simulate_decision(args) == 1

def test_cmd_simulate_decision_invalid_schema(tmp_path):
    plugin_dir = tmp_path / "plugins" / "test_plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "rules.json").write_text(json.dumps({
        "plugin": "test_plugin",
        "version": "1.0.0",
        "domain": "test",
        "actions": {},
        "rules": []
    }))
    
    payload_file = tmp_path / "request.json"
    payload_file.write_text('{"missing": "fields"}')
    
    args = argparse.Namespace(command="simulate-decision", plugin="test_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'))
    assert cmd_simulate_decision(args) == 1

def test_main_validate(monkeypatch):
    monkeypatch.setattr("sys.argv", ["axg", "validate-plugin", "--id", "missing"])
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 1

def test_main_simulate(monkeypatch):
    monkeypatch.setattr("sys.argv", ["axg", "simulate-decision", "--plugin", "p", "--payload", "f"])
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 1


def test_module_entrypoint(monkeypatch):
    monkeypatch.setattr("sys.argv", ["axg", "validate-plugin", "--id", "missing"])
    with pytest.raises(SystemExit) as e:
        runpy.run_module("axg.cli", run_name="__main__")
    assert e.value.code == 1

def test_cmd_validate_plugin_unexpected_error(tmp_path, monkeypatch):
    def mock_load(*args, **kwargs):
        raise RuntimeError("Unexpected boom")
    
    from axg.plugin_loader import PluginLoader
    monkeypatch.setattr(PluginLoader, "load", mock_load)
    
    args = argparse.Namespace(command="validate-plugin", id="test", dir=str(tmp_path / 'plugins'))
    assert cmd_validate_plugin(args) == 1

def test_cmd_simulate_decision_unexpected_error(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "plugins" / "test_plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "rules.json").write_text(json.dumps({
        "plugin": "test_plugin",
        "version": "1.0.0",
        "domain": "test",
        "actions": {},
        "rules": []
    }))
    
    payload_file = tmp_path / "request.json"
    payload_file.write_text(json.dumps({
        "schema_version": "axg.decision_request.v1",
        "execution_id": "123",
        "tenant_id": "tenant_001",
        "app_id": "app",
        "user_id": "user",
        "source": "api",
        "action_type": "create",
        "payload": {}
    }))
    
    def mock_decide(*args, **kwargs):
        raise RuntimeError("Engine boom")
    
    from axg.engine import DecisionEngine
    monkeypatch.setattr(DecisionEngine, "decide", mock_decide)
    
    args = argparse.Namespace(command="simulate-decision", plugin="test_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'))
    assert cmd_simulate_decision(args) == 1
