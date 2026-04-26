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

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        try:
            plugin = self.loader.load(request.plugin_id)
        except PluginLoadError as exc:
            logger.exception("AXG plugin load failed: %s", request.plugin_id)
            return self._fail_safe(request, str(exc))

        triggered_rules = self.rules.evaluate_rules(plugin.rules, request.model_dump())
        decision = self._final_decision(plugin, request, triggered_rules)
        scores = self._scores(plugin, request, triggered_rules)
        response = DecisionResponse(
            execution_id=request.execution_id,
            plugin_version=plugin.version_label,
            decision=decision,
            scores=scores,
            actionable_payload=self._actionable_payload(request, triggered_rules),
            human_readable_reason=self._reason(decision, triggered_rules),
            audit_flags=self._audit_flags(triggered_rules),
            rules_triggered=[
                TriggeredRule(id=rule.id, decision=rule.decision, reason=rule.reason)
                for rule in triggered_rules
            ],
            metadata=request.metadata,
        )
        logger.info(json.dumps(self._decision_log(request, response), sort_keys=True))
        return response

    def _final_decision(
        self,
        plugin: Plugin,
        request: DecisionRequest,
        triggered_rules: list[PolicyRule],
    ) -> Decision:
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

        return DecisionScores(
            llm_confidence=request.llm.confidence,
            final_confidence=self._clamp(request.llm.confidence - confidence_penalty),
            risk_score=self._clamp(risk),
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

    def _reason(self, decision: Decision, triggered_rules: list[PolicyRule]) -> str:
        if triggered_rules:
            return " ".join(rule.reason for rule in triggered_rules)
        if decision == Decision.ALLOW:
            return "No policy rule was triggered and confidence is within the automatic execution threshold."
        if decision == Decision.SUGGEST:
            return "No policy rule was triggered, but confidence recommends assisted execution."
        if decision == Decision.BLOCK:
            return "The proposed action is not permitted for this agent."
        return "The proposal requires confirmation before execution."

    def _audit_flags(self, triggered_rules: list[PolicyRule]) -> list[str]:
        flags: list[str] = []
        for rule in triggered_rules:
            flags.extend(rule.audit_flags or [rule.id])
        return list(dict.fromkeys(flags))

    def _fail_safe(self, request: DecisionRequest, reason: str) -> DecisionResponse:
        response = DecisionResponse(
            execution_id=request.execution_id,
            plugin_version=f"{request.plugin_id}@unavailable",
            decision=Decision.CONFIRM,
            scores=DecisionScores(
                llm_confidence=request.llm.confidence,
                final_confidence=0.0,
                risk_score=1.0,
            ),
            actionable_payload={},
            human_readable_reason=f"AXG failed safe: {reason}",
            audit_flags=["plugin_load_failed"],
            rules_triggered=[],
            metadata=request.metadata,
        )
        logger.warning(
            json.dumps(self._decision_log(request, response), sort_keys=True)
        )
        return response

    def _decision_log(
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
            "app_id": request.app_id,
            "plugin_id": request.plugin_id,
            "plugin_version": response.plugin_version,
            "source": request.source,
            "action_type": request.action_type,
            "decision": response.decision.value,
            "llm_confidence": response.scores.llm_confidence,
            "final_confidence": response.scores.final_confidence,
            "risk_score": response.scores.risk_score,
            "audit_flags": audit_flags,
            "rules_triggered": [rule.id for rule in response.rules_triggered],
            "tenant_id": request.metadata.get("tenant_id"),
        }

    def _clamp(self, value: float) -> float:
        return max(0.0, min(1.0, round(value, 4)))
