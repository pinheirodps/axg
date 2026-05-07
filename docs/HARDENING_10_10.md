# MUAI + AXG Hardening 10/10 Plan

## Objective
Transform MUAI + AXG into an agnostic, auditable, pluggable, and enterprise-ready B2B stack.

## Strategic Principles
- **SOLID**: Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, Dependency Inversion.
- **KISS**: Keep It Simple, Stupid.
- **DRY**: Don't Repeat Yourself.
- **100% Test Coverage**: No code enters master without full regression and unit testing.

## Phase P0: Foundation & Blockers (The Merge Threshold)
- [ ] **AXG SSRF/DNS Hardening**: Close DNS rebinding risks in remote plugin loading.
- [ ] **Node SDK Packaging**: Fix ESM/CJS definitions.
- [ ] **SDK Documentation**: Update READMEs with real API (passport, reason, tenant_id, schema_version).
- [ ] **Passport Verification**: Ensure Python and Node SDKs validate passports with real examples.
- [ ] **Green CI**: Mandatory passing tests for all PRs.

## Phase P1: V1 Contracts
- [ ] `axg.decision_request.v1`
- [ ] `axg.decision_response.v1`
- [ ] `plugin_manifest.v1`
- [ ] `execution_record.v1` (Audit Spine)

## Phase P2: ExecutionRecord Spine
Implement the full audit trail:
- `execution_id`, `tenant_id`, `app_id`, `source`, `requested_by`, `input_hash`.
- `axg_decision`, `risk_level`, `rules_triggered`, `passport_id`, `human_confirmation`.

## Phase P3: Real Pluginization
Proving the agnostic nature of AXG.
- [ ] Plugin structure: `rules.json`, `schemas/`, `examples/`, `tests/`, `README.md`.
- [ ] Official domains: FinNorte, Prospecting, Legal.

## Phase P4: Shadow Mode
- [ ] `shadow`: Log-only.
- [ ] `confirm`: Human-in-the-loop.
- [ ] `enforce`: Hard block/allow.

## Phase P5: Minimum Dashboard
- [ ] Executions by tenant.
- [ ] Decision distribution (ALLOW/CONFIRM/BLOCK).
- [ ] Pending confirmations.
- [ ] Audit trail by `execution_id`.

## Phase P6: SDK & Passport Integrity
- [ ] Payload hash consistency.
- [ ] Expiration validation.
- [ ] Issuer/Audience validation.

## Phase P7: EU Readiness Pack
Create `docs/eu-readiness/` with:
- Trustworthy AI dossier.
- Risk Management.
- Auditability evidence.

---
## Definition Of Done 10/10
- [ ] New tenant without core changes.
- [ ] New AXG plugin via rules/schema/tests only.
- [ ] AXG never fails open for ALLOW.
- [ ] Passport validated by Node and Python SDKs.
- [ ] ExecutionRecord in every action.
- [ ] CI covers core, SDKs, and example plugins.
- [ ] Documentation allows 3rd party integration without internal help.
