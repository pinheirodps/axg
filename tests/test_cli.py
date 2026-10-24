import json
import pytest
import runpy
import argparse
import anyio
from axg.cli import cmd_validate_plugin, cmd_simulate_decision, get_parser, main

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
    assert args.shadow_mode is False

def test_parser_simulate_shadow():
    parser = get_parser()
    args = parser.parse_args(["simulate-decision", "--plugin", "finnorte", "--payload", "test.json", "--shadow-mode"])
    assert args.shadow_mode is True

@pytest.mark.asyncio
async def test_cmd_validate_plugin_success(tmp_path, monkeypatch):
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
    assert await cmd_validate_plugin(args) == 0

@pytest.mark.asyncio
async def test_cmd_validate_plugin_failure(tmp_path):
    args = argparse.Namespace(command="validate-plugin", id="missing_plugin", dir=str(tmp_path / 'plugins'))
    assert await cmd_validate_plugin(args) == 1

@pytest.mark.asyncio
async def test_cmd_simulate_decision_success(tmp_path):
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
    
    args = argparse.Namespace(command="simulate-decision", plugin="test_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'), shadow_mode=False)
    assert await cmd_simulate_decision(args) == 0

@pytest.mark.asyncio
async def test_cmd_simulate_decision_missing_payload(tmp_path):
    args = argparse.Namespace(command="simulate-decision", plugin="test", payload="missing.json", dir=str(tmp_path / 'plugins'), shadow_mode=False)
    assert await cmd_simulate_decision(args) == 1

@pytest.mark.asyncio
async def test_cmd_simulate_decision_plugin_load_error(tmp_path):
    payload_file = tmp_path / "request.json"
    payload_file.write_text("{}")
    
    args = argparse.Namespace(command="simulate-decision", plugin="missing_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'), shadow_mode=False)
    assert await cmd_simulate_decision(args) == 1

@pytest.mark.asyncio
async def test_cmd_simulate_decision_invalid_json(tmp_path):
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
    
    args = argparse.Namespace(command="simulate-decision", plugin="test_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'), shadow_mode=False)
    assert await cmd_simulate_decision(args) == 1

@pytest.mark.asyncio
async def test_cmd_simulate_decision_invalid_schema(tmp_path):
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
    
    args = argparse.Namespace(command="simulate-decision", plugin="test_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'), shadow_mode=False)
    assert await cmd_simulate_decision(args) == 1

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

@pytest.mark.asyncio
async def test_cmd_validate_plugin_unexpected_error(tmp_path, monkeypatch):
    async def mock_load(*args, **kwargs):
        raise RuntimeError("Unexpected boom")
    
    from axg.plugin_loader import PluginLoader
    monkeypatch.setattr(PluginLoader, "load", mock_load)
    
    args = argparse.Namespace(command="validate-plugin", id="test", dir=str(tmp_path / 'plugins'))
    assert await cmd_validate_plugin(args) == 1

@pytest.mark.asyncio
async def test_cmd_simulate_decision_unexpected_error(tmp_path, monkeypatch):
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
    
    async def mock_decide(*args, **kwargs):
        raise RuntimeError("Engine boom")
    
    from axg.engine import DecisionEngine
    monkeypatch.setattr(DecisionEngine, "decide", mock_decide)
    
    args = argparse.Namespace(command="simulate-decision", plugin="test_plugin", payload=str(payload_file), dir=str(tmp_path / 'plugins'), shadow_mode=False)
    assert await cmd_simulate_decision(args) == 1

@pytest.mark.asyncio
async def test_cmd_simulate_decision_shadow_mode(tmp_path, capsys):
    plugin_dir = tmp_path / "plugins" / "test_plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "rules.json").write_text(json.dumps({
        "plugin": "test_plugin", "version": "1.0.0", "domain": "test",
        "actions": {"create": {"required_permissions": [], "base_risk": 0.1}},
        "rules": []
    }))
    payload_file = tmp_path / "request.json"
    payload_file.write_text(json.dumps({
        "schema_version": "axg.decision_request.v1", "execution_id": "1", "tenant_id": "t",
        "app_id": "a", "user_id": "u", "source": "api", "action_type": "create", "payload": {}
    }))
    
    args = argparse.Namespace(command="simulate-decision", plugin="test_plugin", payload=str(payload_file), 
                              dir=str(tmp_path / 'plugins'), shadow_mode=True)
    assert await cmd_simulate_decision(args) == 0
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert response["shadow_mode"] is True


def test_parser_dir_defaults_to_the_bundled_plugins():
    parser = get_parser()
    assert parser.parse_args(["validate-plugin", "--id", "finnorte"]).dir is None
    assert parser.parse_args(["simulate-decision", "--plugin", "p", "--payload", "f"]).dir is None
    help_text = parser._subparsers._group_actions[0].choices["validate-plugin"].format_help()
    assert "<dir>/<plugin_id>/rules.json" in " ".join(help_text.split())
    assert "actions.json" not in parser.format_help()


@pytest.mark.asyncio
async def test_cmd_without_dir_uses_the_bundled_plugins(tmp_path, capsys):
    """`--dir` is the folder that holds the plugin folders; without it the bundled plugins are used."""
    assert await cmd_validate_plugin(argparse.Namespace(command="validate-plugin", id="finnorte", dir=None)) == 0
    assert "Plugin 'finnorte'" in capsys.readouterr().out

    payload_file = tmp_path / "req.json"
    payload_file.write_text(json.dumps({
        "execution_id": "e1", "tenant_id": "t", "app_id": "finnorte", "plugin_id": "finnorte",
        "source": "api", "action_type": "create_expense", "payload": {"amount": 10},
    }), encoding="utf-8")
    args = argparse.Namespace(command="simulate-decision", plugin="finnorte", payload=str(payload_file),
                              dir=None, shadow_mode=False)
    assert await cmd_simulate_decision(args) == 0
    assert json.loads(capsys.readouterr().out)["decision"] in {"ALLOW", "SUGGEST", "CONFIRM", "BLOCK"}


@pytest.mark.asyncio
async def test_without_dir_and_without_a_plugins_folder_the_cli_asks_for_dir(tmp_path, monkeypatch, capsys):
    """A pip install ships no plugins folder: say so instead of 'plugin not found'."""
    from types import SimpleNamespace

    monkeypatch.setattr("axg.cli.PluginLoader", lambda *args: SimpleNamespace(plugins_dir=tmp_path / "missing"))

    assert await cmd_validate_plugin(argparse.Namespace(command="validate-plugin", id="demo", dir=None)) == 1
    assert "Pass --dir" in capsys.readouterr().err

    args = argparse.Namespace(command="simulate-decision", plugin="demo", payload="req.json", dir=None,
                              shadow_mode=False)
    assert await cmd_simulate_decision(args) == 1
    err = capsys.readouterr().err
    assert "pip installs ship none" in err and str(tmp_path / "missing") in err


def test_dir_help_explains_where_the_default_exists():
    help_text = " ".join(get_parser()._subparsers._group_actions[0].choices["simulate-decision"].format_help().split())
    assert "not in a pip install" in help_text and "/app/plugins" in help_text
