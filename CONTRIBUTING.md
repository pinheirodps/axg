# Contributing to AXG

Thanks for helping make AI agent execution safer.

## Ground rules

- **Security issues:** never in public issues. See [SECURITY.md](SECURITY.md).
- **Scope:** AXG is a deterministic decision and attestation layer. It is not an LLM wrapper or an agent framework. Proposals that keep it small and verifiable are the easiest to accept.
- **Compatibility:** the Passport claims, the canonical JSON and the SDK verification rules are a contract across three codebases. Changes to them need a version bump, shared test vectors and migration notes in `CHANGELOG.md`.

## Development

```bash
pip install -e ".[test]"
python -m pytest --cov=axg --cov-report=term-missing --cov-fail-under=98

cd sdks/axg-python-sdk && pip install -e . && pytest
cd sdks/axg-node-sdk && npm ci && npm test
```

Pull request checklist:

- [ ] Tests for new behaviour, including the failure paths. Core coverage stays at or above 98% (it is 100% today).
- [ ] If hashing or Passport claims change: update `tests/fixtures/canonical_vectors.json` and keep `axg/canonical.py` byte-identical to the Python SDK copy.
- [ ] `CHANGELOG.md` updated.
- [ ] No secrets, internal URLs or personal data in code, fixtures or commit messages.

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `chore:`. Mark breaking changes with `!`.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).
