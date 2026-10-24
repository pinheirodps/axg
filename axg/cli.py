import argparse
import json
import sys
from pathlib import Path

import anyio

from axg.audit import verify_audit_chain
from axg.engine import DecisionEngine
from axg.models import DecisionRequest
from axg.plugin_loader import PluginLoadError, PluginLoader

DIR_HELP = (
    "Folder holding one folder per plugin (<dir>/<plugin_id>/rules.json). Defaults to the plugins folder "
    "next to the axg package, which exists in a repository checkout and in the Docker image (/app/plugins) "
    "but not in a pip install"
)


def _plugins_dir(args: argparse.Namespace) -> Path | None:
    """The --dir folder, or None for PluginLoader's default; None also when that default is missing."""
    if args.dir:
        return Path(args.dir)
    default = PluginLoader().plugins_dir
    if not default.is_dir():
        print(
            f"No --dir given and there is no plugins folder at {default} (pip installs ship none). "
            "Pass --dir <folder>, where <folder>/<plugin_id>/rules.json is your policy.",
            file=sys.stderr,
        )
        return None
    return default


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="axg",
        description="AXG - Agent Execution Guard CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate-plugin", help="Validates a plugin's rules.json against the plugin schema")
    validate_parser.add_argument("--id", required=True, help="Plugin ID to validate")
    validate_parser.add_argument("--dir", default=None, help=DIR_HELP)

    simulate_parser = subparsers.add_parser("simulate-decision", help="Simulates a decision request against a plugin")
    simulate_parser.add_argument("--plugin", required=True, help="Plugin ID to use")
    simulate_parser.add_argument("--payload", required=True, help="Path to the request payload JSON file")
    simulate_parser.add_argument("--dir", default=None, help=DIR_HELP)
    simulate_parser.add_argument("--shadow-mode", action="store_true", help="Run simulation in shadow mode")

    audit_parser = subparsers.add_parser("verify-audit", help="Verifies the hash chain of a JSONL audit file")
    audit_parser.add_argument("--file", required=True, help="Path to the AXG_AUDIT_FILE log")

    return parser


async def cmd_validate_plugin(args: argparse.Namespace) -> int:
    base_dir = _plugins_dir(args)
    if base_dir is None:
        return 1
    try:
        loader = PluginLoader(base_dir)
        plugin = await loader.load(args.id)
        print(f"Plugin '{plugin.plugin}' (Version {plugin.version}) is VALID.")
        print(f"Loaded {len(plugin.rules)} rules and {len(plugin.actions)} actions.")
        return 0
    except PluginLoadError as e:
        print(f"Validation FAILED: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected Error: {e}", file=sys.stderr)
        return 1


async def cmd_simulate_decision(args: argparse.Namespace) -> int:
    base_dir = _plugins_dir(args)
    if base_dir is None:
        return 1
    payload_path = Path(args.payload)

    if not payload_path.exists():
        print(f"Error: Payload file '{payload_path}' not found.", file=sys.stderr)
        return 1

    try:
        loader = PluginLoader(base_dir)
        # Attempt to load plugin to fail fast if it's invalid
        await loader.load(args.plugin)
    except PluginLoadError as e:
        print(f"Plugin Load Error: {e}", file=sys.stderr)
        return 1

    try:
        # anyio doesn't provide a top-level sync read, so we use standard open
        # but for consistency with the rest of the app, we could use await anyio.open_file
        # but here we are in a CLI command that just started, so standard open is fine.
        with open(payload_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in payload file: {e}", file=sys.stderr)
        return 1

    # Overwrite plugin_id and shadow_mode
    data["plugin_id"] = args.plugin
    if args.shadow_mode:
        data["shadow_mode"] = True

    try:
        request = DecisionRequest.model_validate(data)
    except Exception as e:
        print(f"Invalid DecisionRequest payload schema: {e}", file=sys.stderr)
        return 1

    engine = DecisionEngine(loader=loader)
    try:
        response = await engine.decide(request)
        print(json.dumps(response.model_dump(mode="json"), indent=2))
        return 0
    except Exception as e:
        print(f"Simulation Failed: {e}", file=sys.stderr)
        return 1


def cmd_verify_audit(args: argparse.Namespace) -> int:
    try:
        ok, line = verify_audit_chain(args.file)
    except OSError as e:
        print(f"Cannot read audit file: {e}", file=sys.stderr)
        return 1
    if ok:
        print(f"Audit chain INTACT: {args.file}")
        return 0
    print(f"Audit chain BROKEN at line {line}: {args.file}", file=sys.stderr)
    return 2


async def async_main() -> None:
    parser = get_parser()
    args = parser.parse_args()

    if args.command == "validate-plugin":
        sys.exit(await cmd_validate_plugin(args))
    elif args.command == "simulate-decision":
        sys.exit(await cmd_simulate_decision(args))
    elif args.command == "verify-audit":
        sys.exit(cmd_verify_audit(args))


def main() -> None:
    anyio.run(async_main)


if __name__ == "__main__":
    main()
