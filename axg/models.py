from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class Decision(str, Enum):
    ALLOW = "ALLOW"
    SUGGEST = "SUGGEST"
    CONFIRM = "CONFIRM"
    BLOCK = "BLOCK"


DECISION_PRECEDENCE = {
    Decision.ALLOW: 0,
    Decision.SUGGEST: 1,
    Decision.CONFIRM: 2,
    Decision.BLOCK: 3,
}


class AgentIdentity(BaseModel):
    id: str
    type: str = "agent"
    permissions: list[str] = Field(default_factory=list)


class LlmSignal(BaseModel):
    model: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    raw_output: dict[str, Any] = Field(default_factory=dict)


class DecisionRequest(BaseModel):
    execution_id: str
    app_id: str
    plugin_id: str
    user_id: str | None = None
    agent: AgentIdentity | None = None
    source: str
    action_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    llm: LlmSignal = Field(default_factory=LlmSignal)
    intent: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DecisionScores(BaseModel):
    llm_confidence: float = Field(ge=0.0, le=1.0)
    final_confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    uncertainty_score: float = Field(default=0.0, ge=0.0, le=1.0)


class TriggeredRule(BaseModel):
    id: str
    decision: Decision
    reason: str


class DecisionResponse(BaseModel):
    schema_version: str = "axg.decision.v1"
    execution_id: str
    plugin_version: str
    decision: Decision
    scores: DecisionScores
    actionable_payload: dict[str, Any]
    human_readable_reason: str
    audit_flags: list[str]
    rules_triggered: list[TriggeredRule]
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuleCondition(BaseModel):
    field: str
    operator: str
    value: Any | None = None


class ConditionGroup(BaseModel):
    all: list[RuleCondition] | None = None
    any: list[RuleCondition] | None = None

    @model_validator(mode="after")
    def require_condition(self):
        if not self.all and not self.any:
            raise ValueError("condition must define at least one of 'all' or 'any'")
        return self


class PolicyRule(BaseModel):
    id: str
    description: str
    condition: ConditionGroup
    decision: Decision
    reason: str
    confidence_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_delta: float = Field(default=0.0, ge=0.0, le=1.0)
    actionable_payload: dict[str, Any] = Field(default_factory=dict)
    audit_flags: list[str] = Field(default_factory=list)


class Thresholds(BaseModel):
    allow_min_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    suggest_min_confidence: float = Field(default=0.65, ge=0.0, le=1.0)
    high_risk_threshold: float = Field(default=0.7, ge=0.0, le=1.0)


class ActionPolicy(BaseModel):
    required_permissions: list[str] = Field(default_factory=list)
    base_risk: float = Field(default=0.25, ge=0.0, le=1.0)


class Plugin(BaseModel):
    plugin: str
    version: str
    domain: str
    thresholds: Thresholds = Field(default_factory=Thresholds)
    actions: dict[str, ActionPolicy] = Field(default_factory=dict)
    rules: list[PolicyRule] = Field(default_factory=list)

    @property
    def version_label(self) -> str:
        return f"{self.plugin}@{self.version}"
