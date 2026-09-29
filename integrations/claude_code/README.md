# AXG × Claude Code (PreToolUse hook)

`axg_pretooluse.py` is a [Claude Code `PreToolUse` hook](https://code.claude.com/docs/en/hooks). Before Claude Code runs a tool (Bash, Edit, Write, MCP tools…), AXG evaluates it against a policy plugin.

| AXG decision | Hook output | Effect in Claude Code |
|---|---|---|
| `ALLOW` | none (default) | Normal permission flow. Use `AXG_HOOK_AUTO_ALLOW=true` to answer `allow`, which skips the user's prompt |
| `SUGGEST` / `CONFIRM` | `ask` + AXG's reason | The user must approve |
| `BLOCK` | `deny` + AXG's reason | The tool does not run; Claude sees why |
| AXG unavailable | `ask` (default) or `deny` (`AXG_HOOK_FAIL_MODE=deny`) | A human decides |

The policy is `plugins/claude-code/rules.json`:
- **Blocked:** destructive shell commands (`rm -rf /`, `mkfs`, `dd if=`…) and remote scripts piped into a shell.
- **Confirmation:** force pushes, hard resets, branch deletion, production deploys, and reading or writing files that look like secrets (`.env`, `id_rsa`, `.pem`, `.key`, `credentials`).
- **Unknown tools** (including undeclared MCP tools) also require confirmation.

Every decision lands in the AXG audit log. With `AXG_AUDIT_FILE`, that log is hash-chained and verifiable with `axg verify-audit`.

## Setup

1. Register the hook as an AXG client:
   ```json
   [{"client_id": "claude-code", "key_sha256": "<sha256 of the key>", "app_ids": ["claude-code"], "permissions": []}]
   ```
2. Set the environment for Claude Code: `AXG_URL`, `AXG_API_KEY`, and optionally `AXG_TENANT_ID`, `AXG_HOOK_AUTO_ALLOW`, `AXG_HOOK_FAIL_MODE`, `AXG_TIMEOUT_SECONDS` (default 3).
3. Add the hook to `.claude/settings.json` (project) or `~/.claude/settings.json` (user):
   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "*",
           "hooks": [
             {"type": "command", "command": "python3 /path/to/axg/integrations/claude_code/axg_pretooluse.py", "timeout": 10}
           ]
         }
       ]
     }
   }
   ```

Keep `AXG_TIMEOUT_SECONDS` below the hook `timeout`. A hook that times out does not block. The script handles AXG's own timeout and falls back to `AXG_HOOK_FAIL_MODE`.

## Adapting the policy

Copy `plugins/claude-code` to your own plugin and point `AXG_PLUGIN_ID` at it:
- Rules match on `action_type` (the tool name) and on `payload.*` (the tool input, e.g. `payload.command`, `payload.file_path`).
- `contains` is case-insensitive.
- Declare every tool you want to allow without confirmation under `actions`.
