from __future__ import annotations

import json
import logging
from typing import Any

from axg.models import (
    DECISION_PRECEDENCE,
    Decision,
    DecisionRequest,
    DecisionResponse,
    DecisionScores,
    Plugin,
    PolicyRule,
    TriggeredRule,
)
from axg.plugin_loader import PluginLoader, PluginLoadError
from axg.rules import RuleEngine
from axg.crypto import sign_decision

logger = logging.getLogger(__name__)

FINANCIAL_WRITE_ACTIONS = {
    "add_expense",
    "add_income",
    "create_transaction",
    "categorize_transaction",
    "detect_subscription",
    "create_expense",
    "create_income",
}

UNCERTAIN_SOURCES = {"whatsapp_bot", "telegram_bot", "chat"}


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

    async def decide(self, request: DecisionRequest) -> DecisionResponse:
        """Evaluates a decision request against the appropriate plugin policies asynchronously."""
        try:
            plugin = await self.loader.load(request.plugin_id)
        except PluginLoadError as exc:
            logger.exception("AXG plugin load failed: %s", request.plugin_id)
            return await self._fail_safe(request, str(exc))

        triggered_rules = self.rules.evaluate_rules(plugin.rules, request.model_dump())
        scores = self._scores(plugin, request, triggered_rules)
        decision = self._final_decision(plugin, request, triggered_rules, scores)
        audit_flags = self._audit_flags(triggered_rules, request, scores)
        actionable_payload = self._actionable_payload(request, triggered_rules)
        token_signing_failed = False
        try:
            # Cryptographic signing is CPU-bound but fast, remains sync
            decision_token = sign_decision(
                execution_id=request.execution_id,
                app_id=request.app_id,
                decision=decision.value,
                action_type=request.action_type,
                actionable_payload=actionable_payload
            )
        except Exception as exc:
            logger.error("AXG failed to generate decision token: %s", str(exc))
            decision_token = None
            token_signing_failed = True
            audit_flags.append("decision_token_signing_failed")
            if DECISION_PRECEDENCE[decision] < DECISION_PRECEDENCE[Decision.CONFIRM]:
                decision = Decision.CONFIRM

        reason = (
            "AXG could not issue a decision token. Confirmation is required before execution."
            if token_signing_failed and decision != Decision.BLOCK
            else self._reason(decision, triggered_rules, request, scores)
        )

        response = DecisionResponse(
            execution_id=request.execution_id,
            plugin_version=plugin.version_label,
            decision=decision,
            passport=decision_token,
            scores=scores,
            actionable_payload=actionable_payload,
            reason=reason,
            audit_flags=audit_flags,
            rules_triggered=[
                TriggeredRule(id=rule.id, decision=rule.decision, reason=rule.reason)
                for rule in triggered_rules
            ],
            metadata=request.metadata,
        )
        logger.info(json.dumps(self.get_decision_log(request, response), sort_keys=True))
        return response

    def _final_decision(
        self,
        plugin: Plugin,
        request: DecisionRequest,
        triggered_rules: list[PolicyRule],
        scores: DecisionScores,
    ) -> Decision:
        if self._requires_uncertainty_confirmation(request, scores):
            return Decision.CONFIRM

        permission_decision = self._permission_decision(plugin, request)
        decisions = [rule.decision for rule in triggered_rules]
        if permission_decision:
            decisions.append(permission_decision)
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
        self, plugin: Plugin, request: DecisionRequest
    ) -> Decision | None:
        policy = plugin.actions.get(request.action_type)
        if not policy:
            return None
        missing_permissions = [
            permission
            for permission in policy.required_permissions
            if not request.agent or permission not in request.agent.permissions
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
            uncertainty_score=self._uncertainty_score(request),
        )

    def _actionable_payload(
        self,
        request: DecisionRequest,
        triggered_rules: list[PolicyRule],
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "proposed_action": request.payload.get(
                "proposed_action", request.action_type
            )
        }
        for key in (
            "transaction_id",
            "merchant",
            "amount",
            "currency",
            "category",
            "description",
        ):
            if key in request.payload:
                payload[key] = request.payload[key]
        if "proposed_category" in request.payload:
            payload["suggested_category"] = request.payload["proposed_category"]
        for rule in triggered_rules:
            payload.update(rule.actionable_payload)
        return payload

    def _reason(
        self,
        decision: Decision,
        triggered_rules: list[PolicyRule],
        request: DecisionRequest,
        scores: DecisionScores,
    ) -> str:
        if self._requires_uncertainty_confirmation(request, scores):
            return (
                "Intent could not be confidently identified. Because this is a "
                "financial write operation, confirmation is required before saving."
            )
        if triggered_rules:
            # Sort by precedence to show most critical reason first
            sorted_rules = sorted(triggered_rules, key=lambda r: DECISION_PRECEDENCE[r.decision], reverse=True)
            return " ".join(rule.reason for rule in sorted_rules)
        if decision == Decision.ALLOW:
            return "No policy rule was triggered and confidence is within the automatic execution threshold."
        if decision == Decision.SUGGEST:
            return "No policy rule was triggered, but confidence recommends assisted execution."
        if decision == Decision.BLOCK:
            return "The proposed action is not permitted for this agent."
        return "The proposal requires confirmation before execution."

    def _audit_flags(
        self,
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
        if self._is_financial_write(request) and scores.uncertainty_score >= 0.7:
            flags.append("financial_write_requires_confirmation")
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
            "audit_flags": audit_flags,
            "rules_triggered": [rule.id for rule in response.rules_triggered],
        }

    def _clamp(self, value: float) -> float:
        return max(0.0, min(1.0, round(value, 4)))

    def _uncertainty_score(self, request: DecisionRequest) -> float:
        intent = request.intent or {}
        score = 0.0
        if intent.get("original") == "unknown":
            score += 0.8
        if intent.get("fallback_used") is True:
            score += 0.2
        if self._is_uncertain_source(request.source):
            score += 0.1
        if (
            self._is_financial_write(request)
            and self._is_uncertain_source(request.source)
            and not intent
        ):
            score = max(score, 0.7)
        return self._clamp(score)

    def _is_uncertain_source(self, source: str) -> bool:
        return source in UNCERTAIN_SOURCES or source.endswith("_bot")

    def _is_financial_write(self, request: DecisionRequest) -> bool:
        resolved_intent = (request.intent or {}).get("resolved")
        return (
            request.action_type in FINANCIAL_WRITE_ACTIONS
            or request.payload.get("proposed_action") in FINANCIAL_WRITE_ACTIONS
            or resolved_intent in FINANCIAL_WRITE_ACTIONS
        )

    def _requires_uncertainty_confirmation(
        self, request: DecisionRequest, scores: DecisionScores
    ) -> bool:
        return self._is_financial_write(request) and scores.uncertainty_score >= 0.7
