# Changelog

## 0.2.0

### Breaking changes

- `POST /v1/decisions` requires an API key (`Authorization: Bearer <key>`). Callers are configured with `AXG_CLIENTS`. During a migration, `AXG_AUTH_MODE=optional` accepts anonymous calls, which are evaluated but never return `ALLOW` or a Passport.
- Passports are issued only for `ALLOW` decisions, and never in shadow mode.
- `sign_decision()` takes keyword arguments and returns `(token, jti)`.
- Payload hashes use canonical JSON: UTF-8 without escaping, ECMAScript number formatting. SDKs from this release verify both v1 and v2 Passports.
- The JWKS `kid` is now the RFC 7638 thumbprint of the key instead of the fixed `axg-key-001`.
- `actionable_payload` now carries every field of the request payload, so the Passport hash covers all of them.

### Added

- Passport v2 claims: `ver`, `jti`, `nbf`, `tenant_id`, `azp`, `policy`.
- Per-caller audience (`app_ids`) and permission ceilings for agents.
- `DecisionResponse.passport_id`. Audit records store it instead of the token.
- JWKS publishes retired keys from `AXG_PREVIOUS_PUBLIC_KEYS` for rotation.
- `AXG_ENV=production` refuses to start without `AXG_PRIVATE_KEY`.
- Remote plugins require `AXG_REMOTE_PLUGIN_ALLOWLIST`. Local plugin ids are validated.
- SDKs: optional replay protection (`replay_cache` / `replayCache`) and shared canonical test vectors (`tests/fixtures/canonical_vectors.json`).

### Fixed

- The Node SDK computed a different payload hash than the Python core for non-ASCII text and integral floats.

### Security

- Admin token compared in constant time.
- The container runs as a non-root user.
- The compose file no longer ships a default admin token.
- CI jobs run with read-only permissions.
