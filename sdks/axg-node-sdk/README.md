# AXG Node.js SDK

Official Node.js SDK for **Agent Execution Guard (AXG)**.

This SDK provides utilities to verify AXG Passport tokens (RS256 JWT) in your backend services.

## Installation

```bash
npm install axg-node-sdk
```

## Usage

```typescript
import { AxgClient } from 'axg-node-sdk';

const axg = new AxgClient('https://axg.your-domain.com');

const token = '...'; // The Passport token from AXG
const payload = { merchant: 'UBER', amount: 15 }; // The data you want to verify

try {
  const claims = await axg.verifyPassport(token, payload, {
    appId: 'your-app-id'
  });
  console.log('Authorized action:', claims.action_type);
} catch (err) {
  console.error('Verification failed:', err.message);
}
```
