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
    context: dict[str, Any] = Field(
        default_factory=dict, description="Facts reported by the caller; rules read them as context.<fact>"
    )
    signed_context: list[str] = Field(
        default_factory=list,
        max_length=8,
        description="JWTs from trusted context providers (AXG_CONTEXT_PROVIDERS); rules read their facts as "
        "verified.<provider>.<fact>",
    )
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
    approval: ApprovalChallenge | None = Field(
        default=None,
        description="For CONFIRM and SUGGEST: a signed ticket that a human approver exchanges for a Passport",
    )
    verified_context: list[str] = Field(
        default_factory=list, description="Providers whose signed context was verified and given to the rules"
    )

    model_config = ConfigDict(populate_by_name=True)


class ExecutionRecord(BaseModel):
    """Audit record of one decision, written by the audit sinks.

    Framework-neutral: it describes the proposal (whatever agent or orchestrator produced it),
    the decision and the execution state, with no assumption about the caller.
    """

    schema_version: Literal["axg.execution_record.v2"] = "axg.execution_record.v2"
    execution_id: str
    tenant_id: str
    app_id: str
    plugin_id: str
    source: str
    requested_by: str | None = Field(default=None, description="user_id, or the agent id when there is no user")
    agent_id: str | None = None
    input_hash: str | None = Field(default=None, description="SHA-256 of the canonical request payload")

    # The proposal under evaluation
    action_type: str
    proposal_model: str | None = Field(default=None, description="Model that proposed the action, if reported")
    proposal_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    intent_fallback_used: bool = False

    # The decision
    decision: Decision
    policy: str = Field(description="plugin@version that produced the decision")
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: str
    rules_triggered: list[str] = Field(default_factory=list)
    audit_flags: list[str] = Field(default_factory=list)
    passport_id: str | None = Field(default=None, description="Passport jti; the token itself is never stored")
    human_confirmation_required: bool = False
    shadow_mode: bool = False
    verified_context: list[str] = Field(
        default_factory=list, description="Providers whose signed context was verified for this decision"
    )

    # The execution, as reported back by the caller
    execution_status: ExecutionStatus = ExecutionStatus.PENDING
    execution_result: Any = None
    error: str | None = None
    created_at: str = Field(description="ISO 8601 UTC time of the decision")
    metadata: dict[str, Any] = Field(default_factory=dict)
    trace_id: str | None = Field(
        default=None, description="W3C trace id of the decision, linking this record to its OpenTelemetry trace"
    )


RuleOperator = Literal["eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "exists", "contains"]


class RuleCondition(BaseModel):
    field: str = Field(description="Dotted path into the request, e.g. payload.amount or agent.id")
    # A typo must fail plugin validation: an operator that silently never matches would disable its rule
    operator: RuleOperator
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
    approver_role: str | None = Field(default=None, description="Role that must approve when this rule asks for a human")


class Thresholds(BaseModel):
    allow_min_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    suggest_min_confidence: float = Field(default=0.65, ge=0.0, le=1.0)
    high_risk_threshold: float = Field(default=0.7, ge=0.0, le=1.0)


class ActionPolicy(BaseModel):
    required_permissions: list[str] = Field(default_factory=list)
    base_risk: float = Field(default=0.25, ge=0.0, le=1.0)
    approver_role: str | None = Field(default=None, description="Role that approves this action when a human must decide")
    required_context: list[str] = Field(
        default_factory=list,
        description="Context providers whose verified facts this action needs; without them the decision is at "
        "least CONFIRM",
    )


class ApprovalPolicy(BaseModel):
    """How a human approves CONFIRM and SUGGEST decisions (docs/approvals.md)."""

    default_role: str = Field(default="end_user", description="Approver role unless an action or rule asks for another")
    ticket_ttl_seconds: int = Field(default=3600, ge=60, le=604800, description="How long an approval ticket stays valid")


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
    approval: ApprovalPolicy = Field(default_factory=ApprovalPolicy)

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
    approval: PassportApproval | None = Field(
        default=None, description="Present when a human approved a CONFIRM or SUGGEST decision"
    )


class ApprovalChallenge(BaseModel):
    """Returned with CONFIRM and SUGGEST: what the approver's side needs to store and show."""

    ticket: str = Field(description="Signed approval ticket (JWT); exchange it at POST /v1/approvals")
    ticket_id: str
    required_role: str
    expires_at: int = Field(description="Unix time after which the ticket is rejected")


class ApprovalTicketClaims(BaseModel):
    """Claims of an approval ticket: a CONFIRM/SUGGEST bound to one payload, awaiting a human."""

    model_config = ConfigDict(extra="forbid")

    iss: Literal["axg-engine"] = "axg-engine"
    typ: Literal["approval"] = "approval"
    sub: str = Field(description="execution_id")
    aud: str = Field(description="app_id")
    azp: str = Field(description="client_id that requested the decision")
    iat: int
    nbf: int
    exp: int
    jti: str = Field(description="ticket id; also the jti of the Passport it can produce")
    tenant_id: str
    plugin_id: str
    policy: str = Field(description="plugin@version that decided; approval is refused if the policy changed")
    decision: Literal["CONFIRM", "SUGGEST"]
    action_type: str
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_role: str
    user_id: str | None = Field(default=None, description="End user the action was proposed for")
    agent_id: str | None = Field(default=None, description="Agent that proposed the action; it can never approve it")


class ApproverIdentity(BaseModel):
    id: str = Field(min_length=1, description="The human who decided, as authenticated by the application")
    role: str = Field(min_length=1)


class ApprovalRequest(BaseModel):
    schema_version: str = "axg.approval_request.v1"
    ticket: str
    actionable_payload: dict[str, Any] = Field(description="Exactly the payload shown to the approver")
    approver: ApproverIdentity
    outcome: Literal["approve", "deny"] = "approve"


class ApprovalResponse(BaseModel):
    schema_version: str = "axg.approval_response.v1"
    execution_id: str
    outcome: Literal["approved", "denied"]
    passport: str | None = None
    passport_id: str | None = None
    actionable_payload: dict[str, Any] = Field(default_factory=dict)


class PassportApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ticket_id: str
    approver_id: str
    approver_role: str


class ApprovalRecord(BaseModel):
    """Audit record of a human approval or denial, written by the audit sinks."""

    schema_version: Literal["axg.approval_record.v1"] = "axg.approval_record.v1"
    execution_id: str
    tenant_id: str
    app_id: str
    action_type: str
    policy: str
    ticket_id: str
    payload_hash: str
    approver_id: str
    approver_role: str
    outcome: Literal["approved", "denied"]
    client_id: str = Field(description="Caller that submitted the approval")
    passport_id: str | None = None
    created_at: str
    trace_id: str | None = None




class IntrospectionRequest(BaseModel):
    """Ask AXG whether a Passport is valid, optionally for one action and one payload (RFC 7662-style)."""

    schema_version: str = "axg.passport_introspection_request.v1"
    passport: str
    action_type: str | None = Field(default=None, description="If set, the Passport must be for this action")
    actionable_payload: dict[str, Any] | None = Field(
        default=None, description="If set, the Passport's payload_hash must match this payload"
    )


class IntrospectionResponse(BaseModel):
    """``active`` is true only for an unexpired ALLOW Passport issued by this AXG and matching the request.

    Single use is not tracked here (AXG is stateless): executors enforce it with a replay cache.
    """

    schema_version: str = "axg.passport_introspection_response.v1"
    active: bool
    reason: str | None = Field(default=None, description="Why the Passport is not active, when it is safe to say")
    claims: dict[str, Any] | None = Field(default=None, description="The Passport claims, when active")


# Resolve forward references to the approval models declared above
DecisionResponse.model_rebuild()
PassportClaimsV2.model_rebuild()
