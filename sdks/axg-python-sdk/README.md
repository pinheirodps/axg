# AXG Python SDK

Verify [AXG](../../README.md) Passports before executing an AI-proposed action.

A Passport is AXG's signed proof that an action was authorized for one app, one tenant, one action and one exact payload. This SDK checks all of that, plus the signature, validity window and single use. See [Passport](../../docs/passport.md) for the concepts.

## Installation

```bash
pip install "axg-python-sdk @ git+https://github.com/pinheirodps/axg@v0.3.0#subdirectory=sdks/axg-python-sdk"
```

The PyPI package (`pip install axg-python-sdk`) is prepared by the release workflow; the [changelog](../../CHANGELOG.md) announces its first upload.

Requires Python 3.11+ (PyJWT with cryptography is installed with it).

## Verify a Passport

Verify against the `actionable_payload` returned by AXG, and execute exactly that payload.

```python
from axg_python_sdk import AxgVerificationError, InMemoryReplayCache, verify_passport

replay_cache = InMemoryReplayCache()  # share one store (e.g. Redis SET NX) across replicas

try:
    claims = verify_passport(
        passport,
        actionable_payload,
        app_id="support",                       # must match the Passport audience
        tenant_id="acme",                       # optional, recommended
        allowed_action_types=["issue_refund"],  # optional, recommended
        jwks_url="https://axg.example.com/.well-known/jwks.json",
        replay_cache=replay_cache,              # optional: reject a Passport used twice
    )
except AxgVerificationError as exc:
    reject(exc.code)  # never execute on failure
else:
    issue_refund(**actionable_payload)
```

`verify_passport` returns the claims (`sub`, `aud`, `tenant_id`, `action_type`, `policy`, `azp`, `jti`…). Pass `public_key=` (PEM) instead of `jwks_url` to verify offline.

### Async services

`AxgClient` keeps a cached JWKS client (keys are refetched only for an unknown `kid`) and runs the check in a worker thread:

```python
from axg_python_sdk import AxgClient

axg = AxgClient("https://axg.example.com")
claims = await axg.verify_passport(passport, actionable_payload, app_id="support", tenant_id="acme")
```

## MCP tools

Inside an MCP tool, check that AXG authorized exactly this tool call. The gateway puts the Passport and the authorized payload in `params._meta` (`io.axg/passport`, `io.axg/actionable_payload`); every argument the tool received must match the authorized payload.

```python
from axg_python_sdk import verify_mcp_tool_call

claims = verify_mcp_tool_call(
    meta=params_meta,
    tool_name="issue_refund",
    arguments=arguments,
    app_id="support",
    jwks_url="https://axg.example.com/.well-known/jwks.json",
)
```

## Approvals

When AXG answers `CONFIRM` or `SUGGEST`, the response carries an approval ticket. After the right person approves, exchange it for a Passport ([Human approvals](../../docs/approvals.md)):

```python
from axg_python_sdk import AxgApprovalError, submit_approval

result = submit_approval(
    "https://axg.example.com", api_key,
    ticket=approval["ticket"], actionable_payload=payload,   # exactly what the approver saw
    approver_id="ana", approver_role="end_user",              # outcome="deny" to refuse
)
passport, to_execute = result["passport"], result["actionable_payload"]
```

`AxgClient(base_url, api_key=...).submit_approval(...)` is the async variant. Refusals raise `AxgApprovalError` with AXG's `status_code` (403 wrong approver, 409 payload or policy changed, 503 AXG unavailable).

## Errors

`AxgVerificationError.code` is one of:

| Code | Meaning |
|---|---|
| `JWT_ERROR` | Bad signature, wrong issuer or audience, expired or not yet valid |
| `DECISION_NOT_ALLOWED` | The token does not carry `ALLOW` |
| `TENANT_ID_MISMATCH`, `ACTION_TYPE_MISMATCH` | Issued for another tenant or action |
| `MISSING_PAYLOAD_HASH`, `PAYLOAD_TAMPERED` | The payload is not the one AXG authorized |
| `MISSING_JTI`, `PASSPORT_REPLAYED` | The token cannot be checked for replay, or was already used |
| `MISSING_PASSPORT`, `ARGUMENTS_MISMATCH` | MCP: no Passport in `_meta`, or arguments differ from the authorized payload |
| `VERIFICATION_FAILED` | Any other failure |

## Compatibility

Verifies Passport v2 (current) and v1 (issued before AXG 0.2). The payload hash uses the same canonical JSON as AXG and the Node SDK, checked against shared test vectors.

## Development

```bash
pip install -e . && pip install pytest pytest-asyncio
pytest
```
