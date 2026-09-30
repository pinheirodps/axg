# Changelog

## Unreleased

### Added

- MCP gateway (`integrations/mcp_gateway`): a Streamable HTTP proxy that puts AXG in front of any MCP server. Every `tools/call` is decided by AXG; `ALLOW` is forwarded with the Passport, `CONFIRM`/`SUGGEST` return the approval ticket in `_meta["io.axg/approval"]`, and a call carrying a Passport is checked through introspection. Other traffic (JSON and SSE) passes through; the client's `Authorization` is never forwarded; batched tool calls are refused. Callers are identified by a verified JWT or a static sidecar identity. It shares the decision core of the AgentCore interceptor and ships in the AXG image. Tested end to end with the official MCP Python SDK.
- Tool results produced by the gateway and the AgentCore interceptor include `resultType: "complete"` for MCP `2026-07-28` clients, which require it, and leave it out for earlier protocol versions.
- Passport introspection (`POST /v1/passports/introspect`, RFC 7662-style): AXG says whether a Passport is valid, optionally for one action and payload, for components that cannot verify RS256 themselves. Callers learn nothing about other apps' Passports. The AgentCore interceptor uses it to accept a `tools/call` that already carries a Passport (for example after a human approval) instead of deciding again, and requires the arguments to match the authorized payload. This completes the approval flow through the gateway. Schemas: `passport_introspection_request.v1`, `passport_introspection_response.v1`.
- Approvals without an orchestrator: `submit_approval` / `AxgClient.submit_approval` (Python) and `submitApproval` / `AxgClient.submitApproval` (Node) exchange a ticket or record a denial, with `AxgApprovalError`. The AgentCore interceptor returns `_meta["io.axg/approval"]` (ticket, role, expiry, payload) on `CONFIRM`/`SUGGEST` tool results. The .NET AGT backend exposes the ticket on `AxgDecisionSink`. `examples/approvals/sqlite_approval_queue.py` is a tested, self-hosted approval queue. `docs/approvals.md` covers where the queue lives, with a LangGraph sketch.
- Stateless human approvals. `CONFIRM` and `SUGGEST` decisions for authenticated callers carry an approval ticket (signed JWT, `typ: axg-approval+jwt`) bound to the payload hash, policy version, required role, end user and agent. `POST /v1/approvals` exchanges an approved ticket for a Passport (`jti` = ticket id, `approval` claim) or records a denial. The caller needs `approvals:approve`. The approver must hold the required role, must be the original user for `end_user` tickets, and can never be the agent. A changed policy or payload needs a fresh decision. Policies declare roles with `approval.default_role`, `actions.<action>.approver_role` and `rules[].approver_role`. Approvals and denials are audited (`approval_record.v1`) and traced (`axg.approve`, `axg.approvals`). New schemas: `approval_ticket_claims.v1`, `approval_request.v1`, `approval_response.v1`, `approval_record.v1`.

## 0.3.0 (2026-09-30)

Upgrade notes: audit consumers read `axg.execution_record.v2`; `AXG_CLIENTS` entries must declare `permissions` explicitly; validate your policies with `axg validate-plugin` (unknown rule operators are now rejected).

### Breaking

- Audit records are now `axg.execution_record.v2`, with framework-neutral fields: `muai_action_type`, `muai_confidence`, `muai_schema_version`, `fallback_used` and `axg_decision` become `action_type`, `proposal_confidence`, `intent_fallback_used` and `decision`. New fields: `plugin_id`, `agent_id`, `proposal_model`, `policy`, `risk_score` and a UTC `created_at`. `execution_record.v1.schema.json` stays published for existing consumers.
- An `AXG_CLIENTS` entry without `permissions` grants its agents no permission (it used to grant any). Set `"permissions": ["*"]` to delegate everything.
- Anonymous callers (`AXG_AUTH_MODE=optional`) can no longer vouch for agent permissions, so actions that require a permission are `BLOCK`ed for them instead of `CONFIRM`ed.
- Policy rules must use a supported operator. An unknown operator used to make its rule silently never match; now the policy fails validation (and AXG answers `CONFIRM` until it is fixed).

### Fixed

- The uncertainty gate returned `CONFIRM` before rules and permissions were weighed, so an agent without the required permission sending an uncertain write got `CONFIRM` instead of `BLOCK`. The gate now only raises a decision to `CONFIRM`; it never lowers a `BLOCK`.
- The image creates `/var/lib/axg` owned by the `axg` user, so an audit volume mounted there is writable by the non-root process.

### Added

- Documentation in `docs/`: concepts, writing policies, Passport, API and contracts, configuration and deployment, security model, observability. The README is rewritten around a working quickstart.
- `plugin_manifest.v1.schema.json`: editor validation and completion for policy files (`"$schema"`). The bundled policies are tested against it.
- `examples/`: quickstart requests (`allow.json`, `block.json`) and a complete example policy (`examples/plugins/support_refunds`), all exercised by the test suite so the documentation cannot drift.
- Images for `linux/amd64` and `linux/arm64`, and continuous deployment of `main` with a health check and automatic rollback. Release images are tagged with the version (`0.3.0`); `latest` follows `main`.
- Release workflow that builds, checks and publishes `axg` and `axg-python-sdk` to PyPI (trusted publishing) and `axg-node-sdk` to npm. The SDKs now share the core version (the Node SDK moves from 1.1.0 to 0.3.0; it had never been published) and ship their license.
- OpenTelemetry: one `axg.decide` span per decision (joined to the caller's W3C `traceparent`), an `axg.rule.triggered` event per matched rule, and the metrics `axg.decisions`, `axg.rules.triggered` and `axg.decision.duration`. The core depends on `opentelemetry-api` only (no-op without an SDK). The `axg[otel]` extra ships in the image and exports over OTLP/HTTP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. `ExecutionRecord.trace_id` links audit records to traces. Payloads, reasons, intents and Passports never reach telemetry.
- `integrations/claude_code`: Claude Code `PreToolUse` hook. BLOCK → `deny`, CONFIRM/SUGGEST → `ask`, ALLOW → normal permission flow (auto `allow` is opt-in), AXG unavailable → `ask` (or `deny`). New example policy `plugins/claude-code`: destructive commands and piped remote scripts are blocked; force pushes, deploys and secret files require confirmation.
- `integrations/agt-dotnet`: `Axg.AgentGovernance`, an `IExternalPolicyBackend` for the Microsoft Agent Governance Toolkit (verified on `Microsoft.AgentGovernance` 5.0.0). ALLOW with a Passport allows; SUGGEST and CONFIRM deny with `RequiresApproval`; BLOCK denies; errors fail closed. `AxgDecisionSink` hands the Passport to the host, because the toolkit drops backend metadata.
- Published JSON Schemas for the wire contracts in `schemas/` (`decision_request.v1`, `decision_response.v1`, `execution_record.v1`, `passport_claims.v2`), generated with `python -m axg.schemas` and checked in CI.
- `PassportClaimsV2` model: `sign_decision` builds Passport claims through it, so the token and the published schema share one definition. It only accepts `decision="ALLOW"`.

## 0.2.1

### Security

- Request bodies are capped by `AXG_MAX_BODY_BYTES` (default 256 KiB, chunked uploads included), with `413` on overflow. Decisions are rate-limited per caller by `AXG_RATE_LIMIT_PER_MINUTE` (default 600), with `429` and `Retry-After`.
- The audit file is hash-chained (`prev_hash` / `record_hash`). New `axg verify-audit` command.
- The webhook audit sink retries up to 3 times.
- Remote plugins: every validated IP is tried on connection failure, and `Host` keeps the original authority, non-default port included.
- Base image pinned by digest. Actions pinned by commit SHA. `pip-audit` and `npm audit` run in CI. Images are published with an SBOM and provenance. Dependabot is enabled.
- Node SDK dev dependencies updated: `npm audit` reports 0 vulnerabilities.
- Added `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `CODEOWNERS`. Removed internal working documents from the repository.

## 0.2.0

### Breaking changes

- `POST /v1/decisions` requires an API key (`Authorization: Bearer <key>`). Callers are configured with `AXG_CLIENTS`. During a migration, `AXG_AUTH_MODE=optional` accepts anonymous calls, which are evaluated but never return `ALLOW` or a Passport.
- Passports are issued only for `ALLOW` decisions, and never in shadow mode.
- `sign_decision()` takes keyword arguments and returns `(token, jti)`.
- Payload hashes use canonical JSON: keys sorted by UTF-16 code units, UTF-8 without escaping, ECMAScript number formatting. SDKs from this release verify both v1 and v2 Passports.
- The JWKS `kid` is now the RFC 7638 thumbprint of the key instead of the fixed `axg-key-001`.
- `actionable_payload` now carries every field of the request payload, so the Passport hash covers all of them.

### Added

- Passport v2 claims: `ver`, `jti`, `nbf`, `tenant_id`, `azp`, `policy`.
- Per-caller audience (`app_ids`) and permission ceilings for agents.
- `DecisionResponse.passport_id`. Audit records store it instead of the token.
- JWKS publishes retired keys from `AXG_PREVIOUS_PUBLIC_KEYS` for rotation.
- `AXG_ENV=production` refuses to start without `AXG_PRIVATE_KEY`.
- Remote plugins require `AXG_REMOTE_PLUGIN_ALLOWLIST`. Entries are parsed and matched by scheme, host, port and path boundary, never by string prefix. Local plugin ids are validated.
- SDKs: optional replay protection (`replay_cache` / `replayCache`) and shared canonical test vectors (`tests/fixtures/canonical_vectors.json`).

### Fixed

- The Node SDK computed a different payload hash than the Python core for non-ASCII text and integral floats.

### Security

- Admin token compared in constant time.
- The container runs as a non-root user.
- The compose file no longer ships a default admin token.
- CI jobs run with read-only permissions.
