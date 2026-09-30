"""A self-hosted approval queue for AXG: SQLite, no orchestrator, about 80 lines.

Run from the repository root:  python examples/approvals/sqlite_approval_queue.py

1. An agent proposes a high-value expense; AXG answers CONFIRM with an approval ticket.
2. The queue stores the ticket and the exact payload.
3. The user sees the payload and approves; the ticket is exchanged for a single-use Passport.
4. The executor verifies the Passport (with a replay cache) before acting.

This example embeds AXG in process. Against an AXG server, replace ``exchange`` with
``axg_python_sdk.submit_approval(axg_url, api_key, ...)`` and ``decide`` with ``POST /v1/decisions``.
"""

import asyncio
import json
import sqlite3
import time

from axg import DecisionEngine, DecisionRequest
from axg.approvals import ApprovalService
from axg.auth import Caller
from axg.crypto import key_manager
from axg.models import ApprovalRequest
from axg_python_sdk import InMemoryReplayCache, verify_passport

# In a service, this identity is your AXG API key (with the approvals:approve permission)
BACKEND = Caller("my-backend", True, frozenset({"*"}), frozenset({"*"}))
engine = DecisionEngine()


class ApprovalQueue:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS approvals (ticket_id TEXT PRIMARY KEY, ticket TEXT, payload TEXT,"
            " required_role TEXT, expires_at INTEGER, status TEXT DEFAULT 'pending')"
        )

    def add(self, decision) -> str:
        approval = decision.approval
        self.db.execute(
            "INSERT INTO approvals (ticket_id, ticket, payload, required_role, expires_at) VALUES (?, ?, ?, ?, ?)",
            (approval.ticket_id, approval.ticket, json.dumps(decision.actionable_payload),
             approval.required_role, approval.expires_at),
        )
        return approval.ticket_id

    def pending(self) -> list[tuple[str, dict, str]]:
        rows = self.db.execute(
            "SELECT ticket_id, payload, required_role FROM approvals WHERE status = 'pending' AND expires_at > ?",
            (int(time.time()),),
        )
        return [(ticket_id, json.loads(payload), role) for ticket_id, payload, role in rows]

    def take(self, ticket_id: str) -> tuple[str, dict]:
        ticket, payload = self.db.execute(
            "SELECT ticket, payload FROM approvals WHERE ticket_id = ? AND status = 'pending'", (ticket_id,)
        ).fetchone()
        return ticket, json.loads(payload)

    def close(self, ticket_id: str, status: str) -> None:
        self.db.execute("UPDATE approvals SET status = ? WHERE ticket_id = ?", (status, ticket_id))


async def decide(request: DecisionRequest):
    return await engine.decide(request, BACKEND)


async def exchange(ticket: str, payload: dict, approver_id: str, approver_role: str):
    response, _record = await ApprovalService(engine.loader).submit(
        ApprovalRequest(ticket=ticket, actionable_payload=payload, approver={"id": approver_id, "role": approver_role}),
        BACKEND,
    )
    return response


async def main() -> dict:
    queue = ApprovalQueue()

    decision = await decide(DecisionRequest(
        execution_id="expense-42", tenant_id="acme", app_id="finnorte", plugin_id="finnorte", user_id="ana",
        source="api", action_type="create_expense", payload={"amount": 5000, "currency": "EUR"},
        agent={"id": "expense-agent", "permissions": ["expense:create"]}, llm={"confidence": 0.95},
    ))
    print(f"AXG: {decision.decision.value} - {decision.reason}")
    ticket_id = queue.add(decision)

    # The user's screen: the exact payload, never a model-written summary
    for pending_id, payload, role in queue.pending():
        print(f"Pending {pending_id[:8]} for role {role}: {payload}")

    ticket, payload = queue.take(ticket_id)
    approved = await exchange(ticket, payload, approver_id="ana", approver_role="end_user")
    queue.close(ticket_id, approved.outcome)

    # The executor: verify, then act
    claims = verify_passport(approved.passport, approved.actionable_payload, "finnorte", tenant_id="acme",
                             public_key=key_manager.public_key, replay_cache=InMemoryReplayCache())
    print(f"Executing {claims['action_type']} approved by {claims['approval']['approver_id']}")
    return claims


if __name__ == "__main__":
    asyncio.run(main())
