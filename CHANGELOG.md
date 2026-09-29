# Changelog

## Unreleased

### Added

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
