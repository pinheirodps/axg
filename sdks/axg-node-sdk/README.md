# AXG Node.js SDK

Verify [AXG](../../README.md) Passports before executing an AI-proposed action.

A Passport is AXG's signed proof that an action was authorized for one app, one tenant, one action and one exact payload. This SDK checks all of that, plus the signature, validity window and single use. See [Passport](../../docs/passport.md) for the concepts.

## Installation

```bash
npm install axg-node-sdk
```

Or build from source:

```bash
git clone https://github.com/pinheirodps/axg && cd axg/sdks/axg-node-sdk
npm ci && npm run build
```

Ships ESM and CommonJS builds with TypeScript types. Tested on Node.js 20.

## Verify a Passport

Verify against the `actionable_payload` returned by AXG, and execute exactly that payload.

```ts
import { AxgClient, AxgVerificationError, InMemoryReplayCache } from 'axg-node-sdk';

const axg = new AxgClient('https://axg.example.com/');
const replayCache = new InMemoryReplayCache(); // share one store across replicas

try {
  const claims = await axg.verifyPassport(passport, actionablePayload, {
    appId: 'support',                       // must match the Passport audience
    tenantId: 'acme',                       // optional, recommended
    allowedActionTypes: ['issue_refund'],   // optional, recommended
    replayCache,                            // optional: reject a Passport used twice
  });
  await issueRefund(actionablePayload);
} catch (err) {
  if (err instanceof AxgVerificationError) reject(err.code); // never execute on failure
  else throw err;
}
```

Without the client: `verifyPassport(token, payload, options, jwksUrl)`. Pass `publicKey` (PEM) in the options to verify offline.

CommonJS works the same way: `const { AxgClient } = require('axg-node-sdk');`.

## MCP tools

```ts
import { verifyMcpToolCall } from 'axg-node-sdk';

const claims = await verifyMcpToolCall(
  request.params._meta,        // carries io.axg/passport and io.axg/actionable_payload
  'issue_refund',
  request.params.arguments,    // must match the authorized payload
  { appId: 'support' },
  'https://axg.example.com/.well-known/jwks.json',
);
```

## Errors

`AxgVerificationError.code` is one of `DECISION_NOT_ALLOWED`, `TENANT_ID_MISMATCH`, `ACTION_TYPE_MISMATCH`, `MISSING_PAYLOAD_HASH`, `PAYLOAD_TAMPERED`, `MISSING_JTI`, `PASSPORT_REPLAYED`, `MISSING_PASSPORT` and `ARGUMENTS_MISMATCH` (same meaning as in the Python SDK). JWT failures keep the [`jose`](https://github.com/panva/jose) code (`ERR_JWT_EXPIRED`, `ERR_JWS_SIGNATURE_VERIFICATION_FAILED`, `ERR_JWT_CLAIM_VALIDATION_FAILED`…); anything else is `VERIFICATION_FAILED`.

## Compatibility

Verifies Passport v2 (current) and v1. The payload hash uses the same canonical JSON as AXG and the Python SDK, checked against shared test vectors.

## Development

```bash
npm ci
npm run build
npm test
```
