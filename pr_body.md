## 🛡️ Summary
This PR evolves **Agent Execution Guard (AXG)** into a production-ready, open-source security foundation for AI agent orchestration. **(Note: This is a fresh PR with a purged and sanitized history to remove build artifacts and node_modules).**

## 🚀 Key Features
- **Standardized Cryptography**: Implemented OIDC-compliant JWKS (/.well-known/jwks.json) and a SOLID KeyManager for secure RSA lifecycle management.
- **Consumer SDKs**: Added official Node.js (TypeScript) and Python SDKs for seamless token verification.
- **Engine Hardening**: Added enriched audit metadata and precedence-based decision sorting. (Remote plugins disabled for security).
- **GHCR Automation**: Added GitHub Actions workflow to automatically build and push Docker images to ghcr.io.
- **100% Quality**: Achieved 100% test coverage across all core modules and SDKs.

## 📦 Docker Usage
The image is now available via GHCR:
`docker pull ghcr.io/pinheirodps/axg:latest`

## 🧪 Verification
- All tests passed (Python Core + Node.js SDK + Python SDK).
- Verified payload integrity with deterministic hashing parity across ecosystems.
