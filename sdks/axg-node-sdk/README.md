# AXG Node.js SDK

Official Node.js SDK for **Agent Execution Guard (AXG)**.

This SDK provides utilities to verify AXG Passport tokens (RS256 JWT) in your backend services.

## Installation

```bash
npm install axg-node-sdk
```

## Usage

```typescript
import { verifyPassport } from 'axg-node-sdk';

const publicKey = '...'; // Your AXG Public Key
const token = '...'; // The token from AXG

try {
  const payload = await verifyPassport(token, publicKey);
  console.log('Authorized action:', payload.action);
} catch (err) {
  console.error('Unauthorized:', err.message);
}
```
