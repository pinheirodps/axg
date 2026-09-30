"""Published JSON Schemas for AXG contracts (integrators validate against these files).

Regenerate after changing a contract model:  python -m axg.schemas
Verify the committed files are current:      python -m axg.schemas --check

Superseded versions (e.g. execution_record.v1) stay in schemas/ unchanged, for existing consumers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import BaseModel

from axg.models import (
    ApprovalRecord,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalTicketClaims,
    IntrospectionRequest,
    IntrospectionResponse,
    DecisionRequest,
    DecisionResponse,
    ExecutionRecord,
    PassportClaimsV2,
    Plugin,
)

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
BASE_ID = "https://raw.githubusercontent.com/pinheirodps/axg/main/schemas"

CONTRACTS: dict[str, type[BaseModel]] = {
    "decision_request.v1": DecisionRequest,
    "decision_response.v1": DecisionResponse,
    "execution_record.v2": ExecutionRecord,
    "passport_claims.v2": PassportClaimsV2,
    "plugin_manifest.v1": Plugin,
    "approval_ticket_claims.v1": ApprovalTicketClaims,
    "approval_request.v1": ApprovalRequest,
    "approval_response.v1": ApprovalResponse,
    "approval_record.v1": ApprovalRecord,
    "passport_introspection_request.v1": IntrospectionRequest,
    "passport_introspection_response.v1": IntrospectionResponse,
}


def render(name: str, model: type[BaseModel]) -> str:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE_ID}/{name}.schema.json",
        **model.model_json_schema(),
    }
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def stale_schemas(directory: Path | None = None) -> list[str]:
    """Names whose committed file is missing or differs from the model."""
    directory = directory or SCHEMA_DIR
    stale = []
    for name, model in CONTRACTS.items():
        path = directory / f"{name}.schema.json"
        if not path.exists() or path.read_text(encoding="utf-8") != render(name, model):
            stale.append(name)
    return stale


def write_schemas(directory: Path | None = None) -> None:
    directory = directory or SCHEMA_DIR
    directory.mkdir(parents=True, exist_ok=True)
    for name, model in CONTRACTS.items():
        (directory / f"{name}.schema.json").write_text(render(name, model), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if "--check" in args:
        stale = stale_schemas()
        if stale:
            print(f"Stale schemas (run `python -m axg.schemas`): {', '.join(stale)}", file=sys.stderr)
            return 1
        print("Schemas are up to date.")
        return 0
    write_schemas()
    print(f"Wrote {len(CONTRACTS)} schemas to {SCHEMA_DIR}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
