from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from axg.models import (
    DECISION_PRECEDENCE,
    ApprovalChallenge,
    Decision,
    DecisionRequest,
    DecisionResponse,
    DecisionScores,
    ExecutionRecord,
    ExecutionStatus,
    Plugin,
    PolicyRule,
    TriggeredRule,
)
from axg.auth import TRUSTED_LOCAL, Caller
from axg.context import VerifiedContext, verify_signed_context
from axg.plugin_loader import PluginLoader, PluginLoadError
from axg.rules import RuleEngine
from axg.crypto import hash_payload, sign_approval_ticket, sign_decision
from axg.telemetry import current_trace_id, observe_decision

logger = logging.getLogger(__name__)

DEFAULT_PENALTY = {
    Decision.ALLOW: 0.0,
    Decision.SUGGEST: 0.1,
    Decision.CONFIRM: 0.25,
    Decision.BLOCK: 0.5,
}


class DecisionEngine:
    def __init__(
        self, loader: PluginLoader | None = None, rules: RuleEngine | None = None
    ):
        self.loader = loader or PluginLoader()
        self.rules = rules or RuleEngine()

    async def decide(self, request: DecisionRequest, caller: Caller = TRUSTED_LOCAL) -> DecisionResponse:
        """Evaluates a decision request against the plugin policies on behalf of ``caller``.

        ``caller`` defaults to the in-process host (library mode). The API passes the
        authenticated client, or ANONYMOUS, which can never obtain ALLOW nor a Passport.
        Each evaluation is traced as an ``axg.decide`` span with decision metrics (no-op
        unless the host installs an OpenTelemetry SDK).
        """
        with observe_decision(request, caller) as observation:
            response = await self._evaluate(request, caller)
            observation.record(response)
            return response

    async def _evaluate(self, request: DecisionRequest, caller: Caller) -> DecisionResponse:
        try:
            plugin = await self.loader.load(request.plugin_id)
        except PluginLoadError as exc:
            logger.exception("AXG plugin load failed: %s", request.plugin_id)
            return await self._fail_safe(request, str(exc))

        verified = await self._verified_context(request)
        triggered_rules = self.rules.evaluate_rules(plugin.rules, self._rule_data(request, verified))
        scores = self._scores(plugin, request, triggered_rules)
        decision = self._final_decision(plugin, request, triggered_rules, scores, caller)
        audit_flags = self._audit_flags(plugin, triggered_rules, request, scores)
        actionable_payload = self._actionable_payload(request, triggered_rules)
        reason = self._reason(plugin, decision, triggered_rules, request, scores)

        if verified.rejected:
            audit_flags.append("signed_context_rejected")
        missing_context = self._missing_context(plugin, request, verified)
        if missing_context:
            audit_flags.append("verified_context_missing")
            # Raises to CONFIRM; never lowers a BLOCK
            if DECISION_PRECEDENCE[decision] < DECISION_PRECEDENCE[Decision.CONFIRM]:
                decision = Decision.CONFIRM
                reason = (
                    f"This action needs verified context from {', '.join(missing_context)}, which was missing or "
                    "invalid. Confirmation is required before execution."
                )

        if decision == Decision.ALLOW and not caller.authenticated:
            decision = Decision.CONFIRM
            audit_flags.append("unauthenticated_caller")
            reason = "The caller is not authenticated. Confirmation is required before execution."

        passport = passport_id = None
        # A Passport authorizes execution: only for ALLOW, and never for shadow evaluations
        if decision == Decision.ALLOW and not request.shadow_mode:
            try:
                passport, passport_id = sign_decision(
                    execution_id=request.execution_id,
                    app_id=request.app_id,
                    tenant_id=request.tenant_id,
                    decision=decision.value,
                    action_type=request.action_type,
                    actionable_payload=actionable_payload,
                    client_id=caller.client_id,
                    policy=plugin.version_label,
                )
            except Exception as exc:
                logger.error("AXG failed to generate passport: %s", str(exc))
                audit_flags.append("passport_signing_failed")
                decision = Decision.CONFIRM
                reason = "AXG could not issue a passport. Confirmation is required before execution."

        approval = None
        # A human can turn CONFIRM/SUGGEST into a Passport, but never for anonymous or shadow requests,
        # nor when AXG could not sign (the same key signs the ticket)
        if (
            decision in (Decision.CONFIRM, Decision.SUGGEST)
            and caller.authenticated
            and not request.shadow_mode
            and "passport_signing_failed" not in audit_flags
        ):
            approval = self._approval_challenge(plugin, request, triggered_rules, decision, actionable_payload, caller)

        response = DecisionResponse(
            execution_id=request.execution_id,
            plugin_version=plugin.version_label,
            decision=decision,
            approval=approval,
            passport=passport,
            passport_id=passport_id,
            scores=scores,
            actionable_payload=actionable_payload,
            reason=reason,
            audit_flags=audit_flags,
            rules_triggered=[
                TriggeredRule(id=rule.id, decision=rule.decision, reason=rule.reason)
                for rule in triggered_rules
            ],
            shadow_mode=request.shadow_mode,
            metadata=request.metadata,
            verified_context=sorted(verified.facts),
        )
        logger.info(json.dumps(self.get_decision_log(request, response), sort_keys=True))
        return response

    async def _verified_context(self, request: DecisionRequest) -> VerifiedContext:
        if not request.signed_context:
            return VerifiedContext()
        # Verification may fetch a provider's JWKS: keep it off the event loop
        return await asyncio.to_thread(
            verify_signed_context, request.signed_context, request.tenant_id, request.user_id
        )

    @staticmethod
    def _rule_data(request: DecisionRequest, verified: VerifiedContext) -> dict[str, Any]:
        # verified.* comes only from checked signatures; the request model has no field of that name
        return {**request.model_dump(), "verified": verified.facts}

    @staticmethod
    def _missing_context(plugin: Plugin, request: DecisionRequest, verified: VerifiedContext) -> list[str]:
        policy = plugin.actions.get(request.action_type)
        return [p for p in (policy.required_context if policy else []) if p not in verified.facts]

    def _approval_challenge(
        self,
        plugin: Plugin,
        request: DecisionRequest,
        triggered_rules: list[PolicyRule],
        decision: Decision,
        actionable_payload: dict[str, Any],
        caller: Caller,
    ) -> ApprovalChallenge | None:
        try:
            return sign_approval_ticket(
                execution_id=request.execution_id,
                app_id=request.app_id,
                tenant_id=request.tenant_id,
                plugin_id=request.plugin_id,
                policy=plugin.version_label,
                decision=decision.value,
                action_type=request.action_type,
                actionable_payload=actionable_payload,
                client_id=caller.client_id,
                required_role=self._approver_role(plugin, request, triggered_rules),
                user_id=request.user_id,
                agent_id=request.agent.id if request.agent else None,
                ttl_seconds=plugin.approval.ticket_ttl_seconds,
            )
        except Exception as exc:
            logger.error("AXG failed to sign an approval ticket: %s", exc)
            return None

    def _approver_role(self, plugin: Plugin, request: DecisionRequest, triggered_rules: list[PolicyRule]) -> str:
        """The strictest matched rule that names a role wins, then the action, then the plugin default."""
        for rule in sorted(triggered_rules, key=lambda r: DECISION_PRECEDENCE[r.decision], reverse=True):
            if rule.approver_role:
                return rule.approver_role
        action = plugin.actions.get(request.action_type)
        return (action.approver_role if action else None) or plugin.approval.default_role

    def _final_decision(
        self,
        plugin: Plugin,
        request: DecisionRequest,
        triggered_rules: list[PolicyRule],
        scores: DecisionScores,
        caller: Caller = TRUSTED_LOCAL,
    ) -> Decision:
        permission_decision = self._permission_decision(plugin, request, caller)
        decisions = [rule.decision for rule in triggered_rules]
        if permission_decision:
            decisions.append(permission_decision)
        # The gate raises an uncertain write to at least CONFIRM; it never lowers a BLOCK
        if self._requires_uncertainty_confirmation(plugin, request, scores):
            decisions.append(Decision.CONFIRM)
        if decisions:
            return max(decisions, key=lambda decision: DECISION_PRECEDENCE[decision])
        if request.action_type not in plugin.actions:
            return Decision.CONFIRM

        if request.llm.confidence >= plugin.thresholds.allow_min_confidence:
            return Decision.ALLOW
        if request.llm.confidence >= plugin.thresholds.suggest_min_confidence:
            return Decision.SUGGEST
        return Decision.CONFIRM

    def _permission_decision(
        self, plugin: Plugin, request: DecisionRequest, caller: Caller = TRUSTED_LOCAL
    ) -> Decision | None:
        policy = plugin.actions.get(request.action_type)
        if not policy:
            return None
        # An agent holds only the permissions its authenticated caller is allowed to grant
        granted = caller.effective_permissions(request.agent.permissions) if request.agent else []
        missing_permissions = [
            permission
            for permission in policy.required_permissions
            if permission not in granted
        ]
        if missing_permissions:
            return Decision.BLOCK
        return None

    def _scores(
        self,
        plugin: Plugin,
        request: DecisionRequest,
        triggered_rules: list[PolicyRule],
    ) -> DecisionScores:
        confidence_penalty = sum(
            rule.confidence_penalty or DEFAULT_PENALTY[rule.decision]
            for rule in triggered_rules
        )
        action_policy = plugin.actions.get(request.action_type)
        risk = (
            action_policy.base_risk
            if action_policy
            else plugin.thresholds.high_risk_threshold
        )
        risk += sum(rule.risk_delta for rule in triggered_rules)
        risk_score = self._clamp(risk)

        risk_level = "low"
        if risk_score >= plugin.thresholds.high_risk_threshold:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"

        return DecisionScores(
            llm_confidence=request.llm.confidence,
            final_confidence=self._clamp(request.llm.confidence - confidence_penalty),
            risk_score=risk_score,
            risk_level=risk_level,
            uncertainty_score=self._uncertainty_score(plugin, request),
        )

    def _actionable_payload(
        self,
        request: DecisionRequest,
        triggered_rules: list[PolicyRule],
    ) -> dict[str, Any]:
        # The whole payload is bound to the Passport hash: no field may change after the decision
        payload: dict[str, Any] = dict(request.payload)
        payload.setdefault("proposed_action", request.action_type)
        if "proposed_category" in request.payload:
            payload["suggested_category"] = request.payload["proposed_category"]
        for rule in triggered_rules:
            payload.update(rule.actionable_payload)
        return payload

    def _reason(
        self,
        plugin: Plugin,
        decision: Decision,
        triggered_rules: list[PolicyRule],
        request: DecisionRequest,
        scores: DecisionScores,
    ) -> str:
        # Most critical rule first
        sorted_rules = sorted(triggered_rules, key=lambda r: DECISION_PRECEDENCE[r.decision], reverse=True)
        rule_reasons = " ".join(rule.reason for rule in sorted_rules)
        if decision == Decision.BLOCK:
            if any(rule.decision == Decision.BLOCK for rule in triggered_rules):
                return rule_reasons
            return "The proposed action is not permitted for this agent."
        if self._requires_uncertainty_confirmation(plugin, request, scores):
            return plugin.uncertainty_gate.reason
        if triggered_rules:
            return rule_reasons
        if decision == Decision.ALLOW:
            return "No policy rule was triggered and confidence is within the automatic execution threshold."
        if decision == Decision.SUGGEST:
            return "No policy rule was triggered, but confidence recommends assisted execution."
        return "The proposal requires confirmation before execution."

    def _audit_flags(
        self,
        plugin: Plugin,
        triggered_rules: list[PolicyRule],
        request: DecisionRequest,
        scores: DecisionScores,
    ) -> list[str]:
        flags: list[str] = []
        for rule in triggered_rules:
            flags.extend(rule.audit_flags or [rule.id])
        intent = request.intent or {}
        if intent.get("original") == "unknown":
            flags.append("unknown_intent")
        if intent.get("fallback_used") is True:
            flags.append("fallback_used")
        if self._requires_uncertainty_confirmation(plugin, request, scores):
            flags.append(plugin.uncertainty_gate.audit_flag)
        
        if request.shadow_mode:
            flags.append("shadow_mode_active")
            
        return list(dict.fromkeys(flags))

    async def _fail_safe(self, request: DecisionRequest, reason: str) -> DecisionResponse:
        """Provides a safe CONFIRM response if policy evaluation fails."""
        response = DecisionResponse(
            execution_id=request.execution_id,
            plugin_version=f"{request.plugin_id}@unavailable",
            decision=Decision.CONFIRM,
            scores=DecisionScores(
                llm_confidence=request.llm.confidence,
                final_confidence=0.0,
                risk_score=1.0,
                risk_level="high",
                uncertainty_score=1.0,
            ),
            actionable_payload={},
            reason=f"AXG failed safe: {reason}",
            audit_flags=["plugin_load_failed"],
            rules_triggered=[],
            metadata=request.metadata,
        )
        logger.warning(
            json.dumps(self.get_decision_log(request, response), sort_keys=True)
        )
        return response

    def get_execution_record(
        self, request: DecisionRequest, response: DecisionResponse
    ) -> ExecutionRecord:
        """Generates the audit record (``axg.execution_record.v2``) of a decision."""
        agent_id = request.agent.id if request.agent else None
        return ExecutionRecord(
            execution_id=request.execution_id,
            tenant_id=request.tenant_id,
            app_id=request.app_id,
            plugin_id=request.plugin_id,
            source=request.source,
            requested_by=request.user_id or agent_id,
            agent_id=agent_id,
            input_hash=hash_payload(request.payload),
            action_type=request.action_type,
            proposal_model=request.llm.model,
            proposal_confidence=request.llm.confidence,
            intent_fallback_used=(request.intent or {}).get("fallback_used") is True,
            decision=response.decision,
            policy=response.plugin_version,
            risk_score=response.scores.risk_score,
            risk_level=response.scores.risk_level,
            rules_triggered=[rule.id for rule in response.rules_triggered],
            audit_flags=response.audit_flags,
            passport_id=response.passport_id,
            human_confirmation_required=response.decision == Decision.CONFIRM,
            shadow_mode=request.shadow_mode,
            verified_context=response.verified_context,
            execution_status=ExecutionStatus.PENDING,
            created_at=datetime.now(timezone.utc).isoformat(),
            metadata=response.metadata,
            trace_id=current_trace_id(),
        )

    def get_decision_log(
        self, request: DecisionRequest, response: DecisionResponse
    ) -> dict[str, Any]:
        audit_flags = response.audit_flags
        return {
            "service": "axg",
            "component": "decision_engine",
            "event": "axg.decision.evaluated",
            "flow": request.metadata.get("flow")
            or f"{request.source}:{request.action_type}",
            "situation": request.metadata.get("situation")
            or (audit_flags[0] if audit_flags else response.decision.value.lower()),
            "execution_id": response.execution_id,
            "tenant_id": request.tenant_id,
            "app_id": request.app_id,
            "plugin_id": request.plugin_id,
            "plugin_version": response.plugin_version,
            "source": request.source,
            "action_type": request.action_type,
            "decision": response.decision.value,
            "llm_confidence": response.scores.llm_confidence,
            "final_confidence": response.scores.final_confidence,
            "risk_score": response.scores.risk_score,
            "risk_level": response.scores.risk_level,
            "uncertainty_score": response.scores.uncertainty_score,
            "shadow_mode": response.shadow_mode,
            "audit_flags": audit_flags,
            "rules_triggered": [rule.id for rule in response.rules_triggered],
        }

    def _clamp(self, value: float) -> float:
        return max(0.0, min(1.0, round(value, 4)))

    def _uncertainty_score(self, plugin: Plugin, request: DecisionRequest) -> float:
        intent = request.intent or {}
        score = 0.0
        if intent.get("original") == "unknown":
            score += 0.8
        if intent.get("fallback_used") is True:
            score += 0.2
        if self._is_uncertain_source(plugin, request.source):
            score += 0.1
        if (
            self._is_gated_write(plugin, request)
            and self._is_uncertain_source(plugin, request.source)
            and not intent
        ):
            score = max(score, plugin.uncertainty_gate.threshold)
        return self._clamp(score)

    def _is_uncertain_source(self, plugin: Plugin, source: str) -> bool:
        gate = plugin.uncertainty_gate
        return source in gate.uncertain_sources or source.endswith(tuple(gate.uncertain_source_suffixes))

    def _is_gated_write(self, plugin: Plugin, request: DecisionRequest) -> bool:
        """The action (or the one the LLM proposed / resolved) is a write this plugin gates."""
        gated = set(plugin.uncertainty_gate.actions)
        resolved_intent = (request.intent or {}).get("resolved")
        return (
            request.action_type in gated
            or request.payload.get("proposed_action") in gated
            or resolved_intent in gated
        )

    def _requires_uncertainty_confirmation(
        self, plugin: Plugin, request: DecisionRequest, scores: DecisionScores
    ) -> bool:
        return (
            self._is_gated_write(plugin, request)
            and scores.uncertainty_score >= plugin.uncertainty_gate.threshold
        )
