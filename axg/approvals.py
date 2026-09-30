"""Human approval of CONFIRM and SUGGEST decisions, with no state in AXG.

A decision that needs a human carries a signed approval ticket bound to the exact actionable
payload. The approver's side (an orchestrator or application) stores the ticket, shows the payload
to the right person, and submits the outcome here. AXG checks the ticket, the caller and the
approver, and turns an approval into a Passport whose jti is the ticket id, so one ticket can never
produce two usable Passports.
"""

from __future__ import annotations

from datetime import datetime, timezone

from axg.auth import Caller
from axg.crypto import ApprovalTicketError, hash_payload, sign_decision, verify_approval_ticket
from axg.models import (
    ApprovalRecord,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalTicketClaims,
    PassportApproval,
)
from axg.plugin_loader import PluginLoader, PluginLoadError
from axg.telemetry import current_trace_id

APPROVE_PERMISSION = "approvals:approve"
END_USER_ROLE = "end_user"


class ApprovalRejected(Exception):
    """The approval cannot be accepted; ``status_code`` and ``detail`` are safe to return."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class ApprovalService:
    def __init__(self, loader: PluginLoader) -> None:
        self.loader = loader

    async def submit(self, request: ApprovalRequest, caller: Caller) -> tuple[ApprovalResponse, ApprovalRecord]:
        # Authenticate before looking at the ticket: anonymous callers learn nothing about it
        if not caller.authenticated:
            raise ApprovalRejected(401, "Approvals require an authenticated caller")
        ticket = self._verified_ticket(request.ticket)
        self._check_caller(ticket, caller)
        self._check_approver(ticket, request)
        await self._check_policy(ticket)

        passport = passport_id = None
        if request.outcome == "approve":
            try:
                passport, passport_id = sign_decision(
                    execution_id=ticket.sub,
                    app_id=ticket.aud,
                    tenant_id=ticket.tenant_id,
                    decision="ALLOW",
                    action_type=ticket.action_type,
                    actionable_payload=request.actionable_payload,
                    client_id=caller.client_id,
                    policy=ticket.policy,
                    jti=ticket.jti,
                    approval=PassportApproval(
                        ticket_id=ticket.jti, approver_id=request.approver.id, approver_role=request.approver.role
                    ),
                )
            except ValueError as exc:
                raise ApprovalRejected(503, "AXG could not issue a Passport. Retry the approval.") from exc

        outcome = "approved" if request.outcome == "approve" else "denied"
        response = ApprovalResponse(
            execution_id=ticket.sub,
            outcome=outcome,
            passport=passport,
            passport_id=passport_id,
            actionable_payload=request.actionable_payload if passport else {},
        )
        record = ApprovalRecord(
            execution_id=ticket.sub,
            tenant_id=ticket.tenant_id,
            app_id=ticket.aud,
            action_type=ticket.action_type,
            policy=ticket.policy,
            ticket_id=ticket.jti,
            payload_hash=ticket.payload_hash,
            approver_id=request.approver.id,
            approver_role=request.approver.role,
            outcome=outcome,
            client_id=caller.client_id,
            passport_id=passport_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            trace_id=current_trace_id(),
        )
        return response, record

    @staticmethod
    def _verified_ticket(token: str) -> ApprovalTicketClaims:
        try:
            return verify_approval_ticket(token)
        except ApprovalTicketError as exc:
            raise ApprovalRejected(400, str(exc)) from exc

    @staticmethod
    def _check_caller(ticket: ApprovalTicketClaims, caller: Caller) -> None:
        if not caller.may_act_for(ticket.aud):
            raise ApprovalRejected(403, "The caller may not submit approvals for this app")
        if APPROVE_PERMISSION not in caller.effective_permissions([APPROVE_PERMISSION]):
            raise ApprovalRejected(403, f"The caller needs the '{APPROVE_PERMISSION}' permission")

    @staticmethod
    def _check_approver(ticket: ApprovalTicketClaims, request: ApprovalRequest) -> None:
        approver = request.approver
        if hash_payload(request.actionable_payload) != ticket.payload_hash:
            raise ApprovalRejected(409, "The payload differs from the one that was decided")
        if approver.role != ticket.required_role:
            raise ApprovalRejected(403, f"This action must be approved by the role '{ticket.required_role}'")
        if ticket.agent_id and approver.id == ticket.agent_id:
            raise ApprovalRejected(403, "An agent cannot approve its own action")
        if ticket.required_role == END_USER_ROLE and ticket.user_id and approver.id != ticket.user_id:
            raise ApprovalRejected(403, "Only the user the action was proposed for can approve it")

    async def _check_policy(self, ticket: ApprovalTicketClaims) -> None:
        """Approve only what the current policy decided: a changed policy needs a fresh decision."""
        try:
            plugin = await self.loader.load(ticket.plugin_id)
        except PluginLoadError as exc:
            raise ApprovalRejected(409, "The policy that decided is no longer available") from exc
        if plugin.version_label != ticket.policy:
            raise ApprovalRejected(409, "The policy changed since the decision. Request a new decision.")
