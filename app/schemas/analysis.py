"""Analysis output schemas: EvidenceItem, Capability, Finding, Contradiction, Uncertainty,
CounterfactualResult, AnalysisReport, AnalysisInput.

This module is the single source of truth for the JSON API *and* the rendered text report
(docs/ANALYSIS_ENGINE_SPEC.md §10).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import (
    ActionClass,
    Confidence,
    EvidenceKind,
    Recoverability,
    RunMode,
    Severity,
    Source,
    VerificationStatus,
)
from app.schemas.entities import (
    Agent,
    Blocker,
    Credential,
    Environment,
    Identity,
    InstructionDoc,
    NetworkEdge,
    Permission,
    Resource,
    Tool,
)
from app.schemas.tolerance import input_config, output_config


class EvidenceItem(BaseModel):
    """A single traceable statement supporting (or negating) a conclusion."""

    model_config = ConfigDict(frozen=True)

    id: str
    kind: EvidenceKind
    subject: str
    predicate: str
    object: str | None = None
    polarity: bool = True
    value: Any = None
    source: Source = Field(default_factory=Source)
    supports: tuple[str, ...] = ()
    note: str | None = None

    @property
    def dedup_key(self) -> tuple[Any, ...]:
        return (
            self.kind.value,
            self.subject,
            self.predicate,
            self.object,
            self.polarity,
            self.source.ref,
        )

    def render(self) -> str:
        """One-line, human-readable form used by the text report."""
        verb = "supports" if self.polarity else "negates"
        target = f" {self.object}" if self.object else ""
        tail = f" -- {self.note}" if self.note else ""
        return (
            f"{self.id} [{self.kind.value}] {self.subject} {self.predicate}{target} ({verb}){tail}"
        )


class ReachabilityView(BaseModel):
    """The four independent truth values (docs/DATA_MODEL.md §7). Never collapsed."""

    model_config = ConfigDict(frozen=True)

    reachable: bool | None = None
    authenticated: bool | None = None
    authorized: bool | None = None
    actionable: bool | None = None

    def render(self) -> str:
        def fmt(value: bool | None) -> str:
            if value is None:
                return "UNKNOWN"
            return "yes" if value else "no"

        return (
            f"reachable={fmt(self.reachable)} authenticated={fmt(self.authenticated)} "
            f"authorized={fmt(self.authorized)} actionable={fmt(self.actionable)}"
        )


class PreconditionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: str
    ref: str
    satisfied: bool | None = None
    note: str | None = None


class Capability(BaseModel):
    """The unit of blast-radius output (docs/DATA_MODEL.md §10)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    action: ActionClass
    target: str
    environment: str | None = None
    path: list[str] = Field(default_factory=list)
    path_hash: str = ""
    preconditions: list[PreconditionResult] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    reachability: ReachabilityView = Field(default_factory=ReachabilityView)
    severity: Severity = Severity.INFO
    severity_basis: list[str] = Field(default_factory=list)
    recoverability: Recoverability = Recoverability.UNKNOWN
    recovery_mechanisms: list[str] = Field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    discovered_by: str = "deterministic"
    state_depth: int = 0
    counterfactual_sensitivity: float = 0.0
    uncertainties: list[str] = Field(default_factory=list)
    cross_environment: bool = False
    derived_from: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(
        default_factory=list,
        description="every entity id that supports this capability (tool, credential, identity, policies)",
    )

    @property
    def triple(self) -> tuple[str, str, str | None]:
        return (self.action.value, self.target, self.environment)

    @property
    def is_direct(self) -> bool:
        return self.state_depth == 0


class Finding(BaseModel):
    """A capability promoted to a reported finding, with its evidence and caveats."""

    model_config = ConfigDict(extra="forbid")

    id: str
    capability_id: str
    title: str
    severity: Severity
    severity_basis: list[str] = Field(default_factory=list)
    action: ActionClass
    target: str
    environment: str | None = None
    recovery: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    evidence_count: dict[str, int] = Field(default_factory=dict)
    confidence: Confidence = Field(default_factory=Confidence)
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    uncertainties: list[str] = Field(default_factory=list)
    discovered_by: str = "deterministic"
    state_depth: int = 0
    reason: str = ""


class Contradiction(BaseModel):
    """Conflicting evidence. Both sides are always reported (docs/ANALYSIS_ENGINE_SPEC.md §7)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    code: str
    subject: str
    message: str
    sides: dict[str, list[str]] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    severity_impact: str = "confidence_reduced"


class Uncertainty(BaseModel):
    """An explicit statement of what could not be determined, and what it weakens."""

    model_config = ConfigDict(extra="forbid")

    id: str
    code: str
    message: str
    affects: list[str] = Field(default_factory=list)
    source_ref: str | None = None


class CounterfactualOp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "remove_tool",
        "remove_credential",
        "reduce_scope",
        "remove_permission",
        "block_network_edge",
        "add_blocker",
        "separate_environment",
        "remove_mcp_server",
        "add_dry_run",
    ]
    target_id: str
    detail: dict[str, Any] | None = None


class CounterfactualResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    op: CounterfactualOp
    capabilities_removed: list[str] = Field(default_factory=list)
    capabilities_downgraded: list[str] = Field(default_factory=list)
    capabilities_added: list[str] = Field(default_factory=list)
    severity_before: Severity = Severity.INFO
    severity_after: Severity = Severity.INFO
    non_monotone_edit: bool = False
    narrative: str = ""


class RejectedClaim(BaseModel):
    """An LLM proposal the deterministic verifier refused to accept.

    Rejected claims are reported, not hidden: that is both an honesty mechanism and the primary
    prompt-injection signal.
    """

    model_config = ConfigDict(extra="forbid")

    claim: str
    reason: str
    source_ref: str | None = None
    origin: str = "agentic"
    injection_signal: bool = False


class InjectionAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ref: str
    pattern: str
    handling: str = "quarantined_as_data"
    excerpt: str | None = None


class TrajectoryStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step: int
    phase: str
    summary: str
    evidence: list[str] = Field(default_factory=list)
    tool: str | None = None
    latency_ms: int | None = None


class RiskSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall_severity: Severity = Severity.INFO
    highest_path: list[str] = Field(default_factory=list)
    capability_count: int = 0
    direct_capabilities: int = 0
    indirect_capabilities: int = 0
    cross_environment_paths: int = 0
    destructive_capabilities: int = 0
    irreversible_capabilities: int = 0
    contradiction_count: int = 0
    uncertainty_count: int = 0
    rejected_claims: int = 0


class LayerSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capabilities: int = 0
    severity_max: Severity = Severity.INFO
    resource_count: int = 0


class LayerComparison(BaseModel):
    """L0/L1/L2 side by side plus the deltas (Rule R1: layers are never collapsed)."""

    model_config = ConfigDict(extra="forbid")

    declared_authority: LayerSummary = Field(default_factory=LayerSummary)
    reachable_authority: LayerSummary = Field(default_factory=LayerSummary)
    effective_capability: LayerSummary = Field(default_factory=LayerSummary)
    delta_notes: list[str] = Field(default_factory=list)


class BaselineComparison(BaseModel):
    """Always present: what the deterministic baseline said vs. what the requested mode added."""

    model_config = ConfigDict(extra="forbid")

    mode_a_capabilities: int = 0
    requested_mode_capabilities: int = 0
    added_by_agentic: list[str] = Field(default_factory=list)
    rejected_agentic: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class NarrativeStatement(BaseModel):
    """One explanatory sentence and the evidence ids that support it.

    The report text is the human artifact; this is the machine-checkable form of the same sentences.
    Explanation faithfulness (§5 of docs/EVALUATION_PLAN.md) is computed from these, because
    regex-scoring free prose is how evaluators end up reporting a number nobody can audit. A test
    asserts the two stay in step: every id here also appears inline in ``report_text``.
    """

    model_config = output_config()

    text: str
    evidence_ids: list[str] = Field(default_factory=list)
    kind: str = "explanation"  # explanation | capability | contradiction | remediation | headline


class RunMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    llm_calls: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    caps_hit: list[str] = Field(default_factory=list)
    estimated_cost_usd: float = 0.0


class AnalysisInput(BaseModel):
    """Everything needed to analyze one agent environment (API request body / scenario body).

    Tolerant by policy: a producer on a newer schema version can add fields without breaking analysis.
    The *envelope* around it (the HTTP request) stays strict, so client typos are still caught early.
    """

    model_config = input_config()

    agent: Agent
    environment: Environment | None = None
    instructions: list[InstructionDoc] = Field(default_factory=list)
    identity: Identity | None = None
    tools: list[Tool] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    permissions: list[Permission] = Field(default_factory=list)
    network: list[NetworkEdge] = Field(default_factory=list)
    blockers: list[Blocker] = Field(default_factory=list)
    scenario_id: str | None = None
    run_mode: RunMode = RunMode.A_DETERMINISTIC

    def entity_ids(self) -> set[str]:
        """All ids present in this input (the verifier rejects claims about anything else)."""
        ids: set[str] = {self.agent.id}
        for collection in (
            self.tools,
            self.credentials,
            self.resources,
            self.permissions,
            self.network,
            self.blockers,
            self.instructions,
        ):
            ids.update(item.id for item in collection)
        if self.identity is not None:
            ids.add(self.identity.id)
        if self.environment is not None:
            ids.add(self.environment.id)
        return ids

    def untrusted_texts(self) -> list[tuple[str, str]]:
        """Every (source_ref, text) pair of untrusted prose in this input.

        Used for injection signalling and for the "untrusted text is quarantined" tests.
        """
        pairs: list[tuple[str, str]] = []
        for tool in self.tools:
            ref = tool.source.ref or tool.id
            for attribute in ("description_untrusted", "notes_untrusted"):
                text = getattr(tool, attribute)
                if text:
                    pairs.append((ref, text))
        for resource in self.resources:
            if resource.notes_untrusted:
                pairs.append((resource.source.ref or resource.id, resource.notes_untrusted))
        for credential in self.credentials:
            if credential.notes_untrusted:
                pairs.append((credential.source.ref or credential.id, credential.notes_untrusted))
        for blocker in self.blockers:
            if blocker.description_untrusted:
                pairs.append((blocker.source.ref or blocker.id, blocker.description_untrusted))
        for document in self.instructions:
            if document.content_untrusted:
                pairs.append((document.source.ref or document.id, document.content_untrusted))
        if self.agent.declared_purpose_untrusted:
            pairs.append(
                (self.agent.source.ref or self.agent.id, self.agent.declared_purpose_untrusted)
            )
        return pairs


class AnalysisReport(BaseModel):
    """The complete analysis result. JSON API and text report are both generated from this."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    status: str = "completed"
    run_mode: RunMode = RunMode.A_DETERMINISTIC
    partial: bool = False
    termination_reason: str = "analysis_complete"
    agent: Agent
    identity: Identity | None = None
    environment: Environment | None = None

    layers: LayerComparison = Field(default_factory=LayerComparison)
    risk_summary: RiskSummary = Field(default_factory=RiskSummary)
    capabilities: list[Capability] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    confirmed_paths: list[list[str]] = Field(default_factory=list)
    potential_paths: list[list[str]] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    uncertainties: list[Uncertainty] = Field(default_factory=list)
    agent_rejected_claims: list[RejectedClaim] = Field(default_factory=list)
    injection_attempts: list[InjectionAttempt] = Field(default_factory=list)
    counterfactuals: list[CounterfactualResult] = Field(default_factory=list)
    baseline_comparison: BaselineComparison = Field(default_factory=BaselineComparison)
    trajectory: list[TrajectoryStep] = Field(default_factory=list)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    report_text: str | None = None
    #: The same explanatory sentences as ``report_text``, in machine-checkable form, so
    #: explanation faithfulness can be scored without regex-scoring prose.
    narrative: list[NarrativeStatement] = Field(default_factory=list)
    scenario_id: str | None = None

    def finding_by_capability(self) -> dict[str, Finding]:
        return {finding.capability_id: finding for finding in self.findings}

    def capability_triples(
        self, *, min_status: VerificationStatus = VerificationStatus.POSSIBLE
    ) -> set[tuple[str, str, str | None]]:
        """Reported capability triples at or above a verification strength."""
        from app.schemas.common import status_rank

        threshold = status_rank(min_status)
        return {
            capability.triple
            for capability in self.capabilities
            if status_rank(capability.verification_status) >= threshold
        }
