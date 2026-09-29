from __future__ import annotations

from enum import Enum, StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class ExecutionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentIdentity(BaseModel):
    id: str
    type: str = "agent"
    permissions: list[str] = Field(default_factory=list)


class LlmSignal(BaseModel):
    model: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    raw_output: dict[str, Any] = Field(default_factory=dict)


class DecisionRequest(BaseModel):
    schema_version: str = "axg.decision_request.v1"
    execution_id: str
    tenant_id: str
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
    shadow_mode: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class DecisionScores(BaseModel):
    llm_confidence: float = Field(ge=0.0, le=1.0)
    final_confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: str = "low" # low, medium, high
    uncertainty_score: float = Field(default=0.0, ge=0.0, le=1.0)


class TriggeredRule(BaseModel):
    id: str
    decision: Decision
    reason: str


class DecisionResponse(BaseModel):
    schema_version: str = "axg.decision_response.v1"
    execution_id: str
    plugin_version: str
    decision: Decision
    passport: str | None = None
    passport_id: str | None = None
    scores: DecisionScores
    actionable_payload: dict[str, Any] = Field(default_factory=dict)
    reason: str
    audit_id: str | None = None
    audit_flags: list[str] = Field(default_factory=list)
    rules_triggered: list[TriggeredRule] = Field(default_factory=list)
    shadow_mode: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class ExecutionRecord(BaseModel):
    schema_version: str = "execution_record.v1"
    execution_id: str
    tenant_id: str
    app_id: str
    source: str
    requested_by: str | None = None
    input_hash: str | None = None

    # MUAI Insights
    muai_schema_version: str = "muai.intent.v1"
    muai_action_type: str | None = None
    muai_confidence: float = 0.0
    fallback_used: bool = False

    # AXG Governance
    axg_decision: str | None = None
    risk_level: str = "low"
    rules_triggered: list[str] = Field(default_factory=list)
    audit_flags: list[str] = Field(default_factory=list)
    passport_id: str | None = None
    human_confirmation_required: bool = False
    shadow_mode: bool = False

    # Final Result
    execution_status: ExecutionStatus = ExecutionStatus.PENDING
    execution_result: Any = None
    error: str | None = None
    created_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


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


class UncertaintyGate(BaseModel):
    """Writes that must be confirmed when the intent behind them is uncertain.

    Domain-specific by design: each plugin lists its own sensitive actions. Without actions,
    the gate never triggers (the engine itself knows no domain).
    """

    actions: list[str] = Field(default_factory=list)
    uncertain_sources: list[str] = Field(default_factory=lambda: ["whatsapp_bot", "telegram_bot", "chat"])
    uncertain_source_suffixes: list[str] = Field(default_factory=lambda: ["_bot"])
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    audit_flag: str = "write_requires_confirmation"
    reason: str = (
        "Intent could not be confidently identified. This action changes data, "
        "so confirmation is required before execution."
    )


class Plugin(BaseModel):
    schema_version: str = "axg.plugin_manifest.v1"
    plugin: str
    version: str
    domain: str
    thresholds: Thresholds = Field(default_factory=Thresholds)
    actions: dict[str, ActionPolicy] = Field(default_factory=dict)
    rules: list[PolicyRule] = Field(default_factory=list)
    uncertainty_gate: UncertaintyGate = Field(default_factory=UncertaintyGate)

    model_config = ConfigDict(populate_by_name=True)

    @property
    def version_label(self) -> str:
        return f"{self.plugin}@{self.version}"


class PassportClaimsV2(BaseModel):
    """Claims of an AXG Passport v2 (RS256 JWT, header ``kid`` = RFC 7638 thumbprint).

    Single source for the tokens issued by ``axg.crypto.sign_decision`` and for the published
    schema ``schemas/passport_claims.v2.schema.json``.
    """

    model_config = ConfigDict(extra="forbid")

    iss: Literal["axg-engine"] = "axg-engine"
    sub: str = Field(description="execution_id")
    aud: str = Field(description="app_id the action is authorized for")
    azp: str = Field(description="client_id of the authenticated caller that requested the decision")
    iat: int
    nbf: int
    exp: int
    jti: str = Field(description="unique id; verifiers enforce single use")
    ver: Literal[2] = 2
    tenant_id: str
    decision: Literal["ALLOW"] = "ALLOW"
    action_type: str
    policy: str = Field(description="plugin@version that produced the decision")
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$", description="SHA-256 of the canonical actionable_payload")
