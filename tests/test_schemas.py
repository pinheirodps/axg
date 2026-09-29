"""Published contract schemas must match the models, and real payloads must validate against them."""

import json

import jwt
import pytest

from axg import schemas
from axg.crypto import key_manager, sign_decision
from axg.models import DecisionRequest


def test_committed_schemas_are_up_to_date():
    assert schemas.stale_schemas() == [], "run `python -m axg.schemas` and commit the result"


def test_check_and_write(tmp_path, capsys):
    assert schemas.stale_schemas(tmp_path) == list(schemas.CONTRACTS)
    schemas.write_schemas(tmp_path)
    assert schemas.stale_schemas(tmp_path) == []

    (tmp_path / "decision_request.v1.schema.json").write_text("{}", encoding="utf-8")
    assert schemas.stale_schemas(tmp_path) == ["decision_request.v1"]


def test_main_check_and_generate(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(schemas, "SCHEMA_DIR", tmp_path)
    assert schemas.main(["--check"]) == 1
    assert "Stale schemas" in capsys.readouterr().err
    assert schemas.main([]) == 0
    assert schemas.main(["--check"]) == 0


def test_every_schema_has_stable_id():
    for name in schemas.CONTRACTS:
        schema = json.loads((schemas.SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))
        assert schema["$id"].endswith(f"/schemas/{name}.schema.json")
        assert schema["$schema"].endswith("2020-12/schema")


def test_issued_passport_matches_published_claims_schema():
    jsonschema = pytest.importorskip("jsonschema")
    token, _ = sign_decision(
        execution_id="e1", app_id="finnorte", tenant_id="t1", decision="ALLOW", action_type="create_expense",
        actionable_payload={"amount": 1}, client_id="muai", policy="finnorte@0.1.0",
    )
    claims = jwt.decode(token, key_manager.public_key, algorithms=["RS256"], audience="finnorte")
    schema = json.loads((schemas.SCHEMA_DIR / "passport_claims.v2.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(claims)


def test_passport_claims_refuse_non_allow_decisions():
    with pytest.raises(ValueError):
        sign_decision(
            execution_id="e1", app_id="a", tenant_id="t", decision="BLOCK", action_type="x",
            actionable_payload={}, client_id="c", policy="p@1",
        )


def test_request_example_validates():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((schemas.SCHEMA_DIR / "decision_request.v1.schema.json").read_text(encoding="utf-8"))
    example = DecisionRequest(
        execution_id="e1", tenant_id="t1", app_id="finnorte", plugin_id="finnorte", source="api", action_type="x",
        agent={"id": "muai:finnorte:api", "type": "service", "permissions": ["expense:create"]},
    ).model_dump(mode="json")
    jsonschema.Draft202012Validator(schema).validate(example)
