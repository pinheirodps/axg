# Contributing to AXG

Thanks for helping make AI agent execution safer.

## Ground rules

- **Security issues:** never in public issues. See [SECURITY.md](SECURITY.md).
- **Scope:** AXG is a deterministic decision and attestation layer. It is not an LLM wrapper or an agent framework. Proposals that keep it small and verifiable are the easiest to accept.
- **Compatibility:** the Passport claims, the canonical JSON and the SDK verification rules are a contract across three codebases. Changes to them need a version bump, shared test vectors and migration notes in `CHANGELOG.md`.

## Development

```bash
pip install -e ".[otel,test]"
python -m pytest --cov=axg --cov=integrations --cov-report=term-missing --cov-fail-under=98

cd sdks/axg-python-sdk && pip install -e . && pytest
cd sdks/axg-node-sdk && npm ci && npm run build && npm test
cd integrations/agt-dotnet && dotnet test
```

Useful commands:

```bash
python -m axg.schemas            # regenerate schemas/ after changing a contract model
python -m axg.schemas --check    # what CI runs
axg validate-plugin --id <plugin> --dir plugins
axg simulate-decision --plugin <plugin> --payload <request.json> --dir plugins
```

Pull request checklist:

- [ ] Tests for new behaviour, including the failure paths. Coverage of `axg` and `integrations` stays at or above 98%.
- [ ] Contract changes (`axg/models.py`): schemas regenerated, and a new schema version for breaking changes.
- [ ] If hashing or Passport claims change: update `tests/fixtures/canonical_vectors.json` and keep `axg/canonical.py` byte-identical to the Python SDK copy.
- [ ] Documentation in `docs/` and examples in `examples/` updated. `tests/test_examples.py` checks that documented examples still decide as documented.
- [ ] `CHANGELOG.md` updated.
- [ ] No secrets, internal URLs or personal data in code, fixtures or commit messages.

## Project layout

```text
axg/            engine, API, auth, Passport crypto, audit, telemetry, CLI
plugins/        bundled example policies
schemas/        published JSON Schemas (generated)
sdks/           Python and Node Passport verification SDKs
integrations/   AWS AgentCore, Microsoft AGT (.NET), Claude Code
examples/       quickstart requests and an example policy
docs/           user documentation
tests/          test suite (the SDKs and integrations have their own)
```

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `chore:`. Mark breaking changes with `!`.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).
