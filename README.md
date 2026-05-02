# 🛡️ AXG - Antigravity eXecution Gateway

**The Open-Source Trust Foundation for AI Agents.**

AXG is a deterministic execution guard that sits between probabilistic AI interpretation and critical system actions. It ensures that every AI-driven decision is cryptographically authorized, auditable, and safe.

> "MUAI interprets. AXG authorizes. Your backend executes only when safe."

---

## 🚀 The Vision: MUAI + AXG

In the modern AI stack, trust is the primary bottleneck. We solve this with a dual-layer approach:

1.  **AXG (Open Source)**: The inspectable trust foundation. It provides the cryptographic Passport (JWT RS256) and enforces deterministic rules.
2.  **MUAI (Commercial/Hosted)**: The multi-tenant interpretation layer. It handles complex LLM orchestration, domain plugins, and provides the intelligence that AXG guards.

**FinNorte** is the living proof of this architecture, processing high-value financial transactions with 100% cryptographic certainty.

---

## ✨ Core Features

-   **Deterministic Scoring**: Risk, Uncertainty, and Confidence scores calculated without LLM hallucination risk.
-   **AXG Passport**: RS256-signed execution proofs with deterministic `payload_hash` to prevent tampering.
-   **Standard JWKS**: Built-in support for OIDC-standard key discovery at `/.well-known/jwks.json`.
-   **Remote Plugins**: Support for loading security policies from local files or remote URIs.
-   **Fail-Safe Design**: Never fails open. Defaults to `CONFIRM` or `BLOCK` on any infrastructure failure.
-   **100% Test Coverage**: A hardened codebase verified for mission-critical reliability.

---

## 📦 Developer Experience (SDKs)

Integrate AXG into your app in minutes using our official SDKs:

### Node.js (TypeScript)
```bash
npm install axg-node-sdk
```
```typescript
import { AxgClient } from 'axg-node-sdk';
const client = new AxgClient('https://your-axg-instance.com');
const passport = await client.verifyPassport(token, payload, { appId: 'your-app' });
```

### Python
```bash
pip install axg-python-sdk
```
```python
from axg_python_sdk import AxgClient
client = AxgClient("https://your-axg-instance.com")
passport = await client.verify_passport(token, payload, app_id="your-app")
```

---

## 🛠️ Quick Start

### 1. Run with Docker
```bash
docker-compose up -d
```

### 2. Verify Key Discovery
```bash
curl http://localhost:8090/.well-known/jwks.json
```

### 3. Request a Decision
```bash
curl -X POST http://localhost:8090/v1/decisions -H "Content-Type: application/json" -d @examples/request.json
```

---

## 🔧 Architecture

AXG evaluates decisions based on **Plugins**. A plugin is a declarative JSON policy that defines thresholds and rules.

```json
{
  "plugin": "finnorte",
  "rules": [
    {
      "id": "high_value_guard",
      "condition": { "all": [{ "field": "payload.amount", "operator": "gte", "value": 1000 }] },
      "decision": "CONFIRM",
      "reason": "High-value action requires explicit human confirmation."
    }
  ]
}
```

---

## 📜 License

Apache-2.0 - See [LICENSE](LICENSE) for details.

---

Built with ❤️ by the **Antigravity Team** for the next generation of trustworthy AI.
