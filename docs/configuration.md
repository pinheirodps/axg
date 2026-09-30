# Configuration and deployment

AXG is configured through environment variables. Secrets (keys, tokens, client hashes) always come from the environment or a secret store, never from files in the image.

## Environment variables

### Callers and keys

| Variable | Default | Description |
|---|---|---|
| `AXG_CLIENTS` | empty | JSON list of callers: `[{"client_id": "...", "key_sha256": "...", "app_ids": [...], "permissions": [...]}]` |
| `AXG_AUTH_MODE` | `required` | `required` rejects calls without a valid key (`401`). `optional` is for migrations: anonymous calls are evaluated but never get `ALLOW` or a Passport |
| `AXG_ENV` | `development` | `production` makes a missing `AXG_PRIVATE_KEY` fatal at startup |
| `AXG_PRIVATE_KEY`, `AXG_PUBLIC_KEY` | ephemeral | RSA key pair in PEM for signing Passports (`\n` escapes accepted) |
| `AXG_PREVIOUS_PUBLIC_KEYS` | empty | JSON list of retired public keys still published in the JWKS during [rotation](passport.md#key-management) |
| `AXG_ADMIN_TOKEN` | unset | Enables `POST /v1/plugins/reload`. Unset means the endpoint always answers `401` |

Each `AXG_CLIENTS` entry:

| Field | Description |
|---|---|
| `client_id` | Name of the caller. It appears in Passports (`azp`), logs, traces and metrics |
| `key_sha256` | SHA-256 (hex) of the caller's API key. AXG never stores the key itself |
| `app_ids` | Apps the caller may request decisions for (`*` for any). Anything else gets `403` |
| `permissions` | Ceiling on the agent permissions this caller may grant (`*` for any). Permissions beyond it are ignored. Omitted means none |

Create a key and its entry:

```bash
KEY=$(openssl rand -hex 32)          # give this to the caller, over a secure channel
HASH=$(printf %s "$KEY" | sha256sum | cut -d' ' -f1)
echo "[{\"client_id\":\"support-bot\",\"key_sha256\":\"$HASH\",\"app_ids\":[\"support\"],\"permissions\":[\"refunds:write\"]}]"
```

### Policies

| Variable | Default | Description |
|---|---|---|
| `ENABLE_REMOTE_PLUGINS` | `false` | Allow `plugin_id` to be an HTTPS URL |
| `AXG_REMOTE_PLUGIN_ALLOWLIST` | empty | Comma-separated allowed origins, optionally with a path (`https://policies.example.com/axg/`) |

Local policies are read from `plugins/` next to the package, which is `/app/plugins` in the image.

### Audit

| Variable | Description |
|---|---|
| `AXG_AUDIT_FILE` | Path of the hash-chained JSONL audit log. Put it on a persistent volume |
| `AXG_AUDIT_WEBHOOK` | URL that receives each audit record (`POST`, 3 attempts) |
| `AXG_AUDIT_WEBHOOK_TOKEN` | Optional bearer token for the webhook |

### Limits

| Variable | Default | Description |
|---|---|---|
| `AXG_MAX_BODY_BYTES` | 262144 | Maximum request body, chunked uploads included (`413` above it) |
| `AXG_RATE_LIMIT_PER_MINUTE` | 600 | Decisions per caller per minute, per process (`429`). `0` disables |

### Observability

| Variable | Description |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Turns on OpenTelemetry export over OTLP/HTTP. The other standard `OTEL_*` variables apply. See [Observability](observability.md) |

### Server

| Variable | Default | Description |
|---|---|---|
| `PORT` | 8090 | Listening port inside the container |

## Docker

The image `ghcr.io/pinheirodps/axg` is published for `linux/amd64` and `linux/arm64`, with an SBOM and build provenance. It runs as a non-root user.

| Tag | Content |
|---|---|
| `latest`, `main` | The current `main` branch |
| `sha-<commit>` | One specific commit (immutable; use it in production) |
| `<x.y.z>` | A release, for example `0.3.0` |

```bash
docker run -d --name axg -p 8090:8090 \
  -e AXG_ENV=production \
  -e AXG_PRIVATE_KEY="$(cat axg-private.pem)" \
  -e AXG_CLIENTS="$AXG_CLIENTS" \
  -e AXG_AUDIT_FILE=/var/lib/axg/audit.jsonl \
  -v axg-audit:/var/lib/axg \
  -v "$PWD/policies:/app/plugins:ro" \
  ghcr.io/pinheirodps/axg:0.3.0
```

The repository's [`docker-compose.yml`](../docker-compose.yml) runs the same setup for local development. The container health check calls `GET /health`.

## Production checklist

- [ ] `AXG_ENV=production` and a persistent `AXG_PRIVATE_KEY` from a secret store.
- [ ] One `AXG_CLIENTS` entry per caller, with the narrowest `app_ids` and `permissions` ceiling.
- [ ] `AXG_AUTH_MODE=required` (the default). Use `optional` only while migrating callers to keys.
- [ ] `AXG_AUDIT_FILE` on a persistent volume, with `axg verify-audit` run on a schedule.
- [ ] Policies mounted read-only, validated in CI with `axg validate-plugin`, and versioned.
- [ ] Remote policies disabled unless needed, and then allow-listed.
- [ ] AXG reachable only from your callers (private network or an authenticating proxy with TLS).
- [ ] An image pinned by `sha-<commit>` or version, not `latest`.
- [ ] `OTEL_EXPORTER_OTLP_ENDPOINT` set, with alerts on `axg.decisions` by decision and on `ERROR` spans.
- [ ] Executors verify every Passport with a replay cache shared across replicas.

## Scaling

AXG is stateless apart from two per-process caches: loaded policies and the rate limiter. Run several replicas behind a load balancer. All of them must share the same `AXG_PRIVATE_KEY` and `AXG_CLIENTS`. The rate limit applies per replica, and policy reloads must be sent to every replica (or roll the deployment).
