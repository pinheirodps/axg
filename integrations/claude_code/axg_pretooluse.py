#!/usr/bin/env python3
"""Claude Code PreToolUse hook: AXG decides before Claude Code runs a tool (standard library only).

Mapping (hookSpecificOutput.permissionDecision):
  ALLOW              -> no decision: Claude Code's normal permission flow applies
                        ("allow", which skips the user's prompt, only with AXG_HOOK_AUTO_ALLOW=true)
  SUGGEST / CONFIRM  -> "ask": the user must approve, with AXG's reason
  BLOCK              -> "deny": the tool does not run and Claude sees the reason
  AXG unavailable    -> "ask" (fail to a human); AXG_HOOK_FAIL_MODE=deny blocks instead

Environment:
  AXG_URL, AXG_API_KEY          AXG endpoint and this hook's key in AXG_CLIENTS   (required)
  AXG_APP_ID                    Passport audience       (default: claude-code)
  AXG_PLUGIN_ID                 policy plugin           (default: claude-code)
  AXG_TENANT_ID                 tenant                  (default: local)
  AXG_TIMEOUT_SECONDS           default 3 (keep below the hook timeout)
  AXG_HOOK_AUTO_ALLOW           "true" to turn ALLOW into "allow"
  AXG_HOOK_FAIL_MODE            "ask" (default) or "deny"
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any


def decision_request(event: dict[str, Any]) -> dict[str, Any]:
    app_id = os.environ.get("AXG_APP_ID", "claude-code")
    agent = event.get("agent_type") or "main"
    return {
        "execution_id": f"claude-code-{event.get('tool_use_id') or uuid.uuid4()}",
        "tenant_id": os.environ.get("AXG_TENANT_ID", "local"),
        "app_id": app_id,
        "plugin_id": os.environ.get("AXG_PLUGIN_ID", "claude-code"),
        "user_id": os.environ.get("USER") or os.environ.get("USERNAME"),
        "agent": {"id": f"claude-code:{agent}", "type": "agent", "permissions": []},
        "source": "claude-code",
        "action_type": event.get("tool_name", ""),
        "payload": event.get("tool_input") or {},
        # An explicit tool call is not an LLM guess: rules decide
        "llm": {"confidence": 1.0},
        "metadata": {
            "flow": "claude-code:pre_tool_use",
            "session_id": event.get("session_id"),
            "cwd": event.get("cwd"),
            "permission_mode": event.get("permission_mode"),
        },
    }


def ask_axg(request: dict[str, Any]) -> dict[str, Any]:
    http_request = urllib.request.Request(
        f"{os.environ['AXG_URL'].rstrip('/')}/v1/decisions",
        data=json.dumps(request).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {os.environ['AXG_API_KEY']}"},
        method="POST",
    )
    with urllib.request.urlopen(http_request, timeout=float(os.environ.get("AXG_TIMEOUT_SECONDS", "3"))) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _output(decision: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def decide(event: dict[str, Any]) -> dict[str, Any] | None:
    """Hook output for this event, or None to leave the decision to Claude Code."""
    try:
        axg = ask_axg(decision_request(event))
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
        mode = "deny" if os.environ.get("AXG_HOOK_FAIL_MODE", "ask").lower() == "deny" else "ask"
        return _output(mode, f"AXG could not evaluate this action ({exc}); a human must decide.")

    verdict = axg.get("decision")
    reason = f"AXG {verdict}: {axg.get('reason') or 'no reason given'}"
    if verdict == "BLOCK":
        return _output("deny", reason)
    if verdict == "ALLOW":
        auto_allow = os.environ.get("AXG_HOOK_AUTO_ALLOW", "").lower() == "true"
        return _output("allow", reason) if auto_allow else None
    return _output("ask", reason)  # CONFIRM, SUGGEST or anything unexpected


def main(stdin=None, stdout=None) -> int:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    try:
        event = json.loads(stdin.read() or "{}")
    except json.JSONDecodeError:
        event = {}
    result = decide(event)
    if result is not None:
        stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
