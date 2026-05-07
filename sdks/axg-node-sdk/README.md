# AXG Node.js SDK

Official Node.js SDK for **Agent Execution Guard (AXG)**.

This SDK provides utilities to verify **AXG Passport** tokens (RS256 JWT) in your backend services, ensuring that AI-driven actions are authorized and immutable.

## Installation

```bash
npm install axg-node-sdk
```

## Features

- **Dual Packaging**: Supports both ESM and CommonJS.
- **Passport Verification**: Cryptographic verification of AXG decisions.
- **Payload Integrity**: Ensures the executed payload matches the authorized one.

## Usage (ESM)

```typescript
import { verifyPassport } from 'axg-node-sdk';

const passport = '...'; // The Passport token from AXG DecisionResponse
const actualPayload = { merchant: 'UBER', amount: 15 };

try {
  const result = await verifyPassport(passport, actualPayload, {
    tenantId: 'tenant_001',
    appId: 'muai',
    actionType: 'finance.payment'
  });
  
  console.log('Authorized by rules:', result.rules_triggered);
  console.log('Decision Source:', result.source);
} catch (err) {
  console.error('Action BLOCKED or Passport INVALID:', err.message);
}
```

## Usage (CommonJS)

```javascript
const { verifyPassport } = require('axg-node-sdk');

// ... same logic as above
```

## V1 Contract Support
The SDK fully supports the `axg.decision_response.v1` schema including `execution_id`, `passport_id`, and `risk_level`.
