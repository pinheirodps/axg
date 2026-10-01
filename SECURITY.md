# Security Policy

AXG issues cryptographic Passports that other systems trust before executing actions, so we treat security reports as our highest priority.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | ✅ |
| 0.3.x | ✅ |
| 0.2.x | ❌ Upgrade: see the upgrade notes for 0.3.0 in the [changelog](CHANGELOG.md) |
| < 0.2 | ❌ Upgrade: callers are unauthenticated and Passports are not bound to a tenant |

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub private vulnerability reporting).

Please include affected versions, a description of the impact, and steps to reproduce, or a proof of concept.

What to expect:

- Acknowledgement within **3 business days**.
- An initial assessment within **10 business days**.
- A fix, and a GitHub Security Advisory crediting you (unless you prefer otherwise), coordinated with you before any public disclosure.

## Scope

In scope:

- The decision engine and HTTP API (`axg/`)
- Passport issuance and verification, including the Python and Node SDKs in `sdks/`
- Canonical hashing, key management and JWKS
- Plugin loading and the rule engine
- The integrations in `integrations/` (AgentCore interceptor, AGT backend, Claude Code hook)
- The published container image

Out of scope:

- Deployments that ignore the [security model](docs/security-model.md), for example `AXG_AUTH_MODE=optional` in production, or AXG exposed without TLS.
- Findings that need a compromised signing key or host.
- Denial of service through traffic volume alone. Please still report bypasses of the request size and rate limits.

## Hardening checklist for operators

- Set `AXG_ENV=production` and provide `AXG_PRIVATE_KEY`, ideally from a secret manager.
- Configure `AXG_CLIENTS` with one key per caller, the narrowest `app_ids`, and permission ceilings. Keep `AXG_AUTH_MODE=required`.
- Keep `ENABLE_REMOTE_PLUGINS` off unless needed. If it is on, allowlist exact origins.
- Enable `AXG_AUDIT_FILE` and verify it regularly with `axg verify-audit --file <path>`.
- Consumers verify Passports with the SDKs and a `replay_cache` / `replayCache` shared across replicas.
