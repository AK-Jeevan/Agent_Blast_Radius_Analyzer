"""The agentic analysis pipeline: propose, verify, merge, and record everything.

Run modes map to which reasoning tasks are enabled:

===================  =====================================================
``A_deterministic``  none (this layer is not invoked)
``B_interpret``      semantics only -- what do tools do that they do not declare?
``C_agentic``        semantics + composition -- what do tool *combinations* reach?
``D_full``           semantics + composition + stateful
===================  =====================================================

Two rules hold in every mode:

1. **Proposals are never findings.** Only claims that survive :class:`ClaimVerifier` are merged.
2. **Nothing is hidden.** Rejected claims, injection signals, and the step-by-step trajectory all
   reach the report, so a reader can audit what the model contributed and what was refused.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.agents import prompts
from app.agents.client import LLMClient, ScriptedLLM, UsageLedger, build_client
from app.agents.verifier import ClaimVerifier, VerificationOutcome
from app.analyzers.authz import PolicyEvaluator
from app.analyzers.credentials import analyse_credentials
from app.analyzers.evidence import EvidenceLedger
from app.analyzers.reachability import ReachabilityAnalyzer
from app.config import Settings, get_settings
from app.graph.builder import build_graph
from app.schemas.analysis import (
    AnalysisInput,
    AnalysisReport,
    Capability,
    EvidenceItem,
    InjectionAttempt,
    RejectedClaim,
    RunMetrics,
    TrajectoryStep,
)
from app.schemas.common import RunMode, severity_rank
from app.utils.ids import canonical_json

#: Which reasoning tasks each run mode enables (the ablation's independent variable).
MODE_TASKS: dict[RunMode, tuple[str, ...]] = {
    RunMode.A_DETERMINISTIC: (),
    RunMode.B_INTERPRET: ("semantics",),
    RunMode.C_AGENTIC: ("semantics", "composition"),
    RunMode.D_FULL: ("semantics", "composition", "stateful"),
}

_TASK_PROMPTS = {
    "semantics": (prompts.SEMANTICS_INSTRUCTION, prompts.SEMANTICS_SCHEMA),
    "composition": (prompts.COMPOSITION_INSTRUCTION, prompts.COMPOSITION_SCHEMA),
    "stateful": (prompts.STATEFUL_INSTRUCTION, prompts.STATEFUL_SCHEMA),
}


@dataclass
class AgenticResult:
    """What the agentic layer contributed, plus the audit trail for how."""

    capabilities: list[Capability] = field(default_factory=list)
    rejected_claims: list[RejectedClaim] = field(default_factory=list)
    trajectory: list[TrajectoryStep] = field(default_factory=list)
    injection_attempts: list[InjectionAttempt] = field(default_factory=list)
    metrics: RunMetrics = field(default_factory=RunMetrics)
    evidence: list[EvidenceItem] = field(default_factory=list)
    client_name: str = "none"
    proposals_seen: int = 0


class AgenticAnalyzer:
    """Runs the reasoning tasks for one run mode and returns only verified additions."""

    def __init__(
        self,
        analysis_input: AnalysisInput,
        baseline: AnalysisReport,
        *,
        mode: RunMode = RunMode.D_FULL,
        settings: Settings | None = None,
        client: LLMClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.mode = mode
        self.client = client or build_client(self.settings)
        self.analysis_input = analysis_input
        self.baseline = baseline
        # The agentic verifier extends the *same* evidence space as the deterministic run.
        self.ledger = EvidenceLedger.from_items(list(baseline.evidence))
        self.environment = build_graph(analysis_input)
        self.reachability = ReachabilityAnalyzer(self.environment)
        self.evaluator = PolicyEvaluator(analysis_input)
        self.credentials = analyse_credentials(analysis_input)
        self.verifier = ClaimVerifier(
            analysis_input,
            self.environment,
            self.ledger,
            self.reachability,
            self.evaluator,
            self.credentials,
        )
        self.usage = UsageLedger()
        self.result = AgenticResult(client_name=self.client.name)
        self._step = 0
        self._fallback: ScriptedLLM | None = None

    # --- loop plumbing ------------------------------------------------------------------
    def _record(self, phase: str, summary: str) -> None:
        self._step += 1
        self.result.trajectory.append(TrajectoryStep(step=self._step, phase=phase, summary=summary))

    def _ask(self, task: str) -> dict[str, Any]:
        envelope = prompts.build_envelope(self.analysis_input)
        instruction, schema = _TASK_PROMPTS[task]
        response = self.client.complete(
            system=prompts.system_prompt(instruction, envelope),
            user=prompts.user_prompt(self.analysis_input, self.baseline),
            schema_hint=canonical_json(schema),
        )
        self.usage.record(response, label=task)
        if isinstance(response.payload, dict) and response.payload.get("error"):
            # The model is unavailable or misconfigured. Degrade to the scripted stand-in for this
            # task and say so in the trajectory, rather than failing the whole analysis or quietly
            # pretending an LLM contributed.
            self._record(
                "DEGRADE", f"model call failed ({response.payload['error']}); using stand-in"
            )
            if self._fallback is None:
                self._fallback = ScriptedLLM()
            fallback_response = self._fallback.complete(
                system=prompts.system_prompt(instruction, envelope),
                user=prompts.user_prompt(self.analysis_input, self.baseline),
                schema_hint=canonical_json(schema),
            )
            self.usage.record(fallback_response, label=f"{task}:fallback")
            return fallback_response.payload
        return response.payload

    # --- task execution -----------------------------------------------------------------
    def _run_task(self, task: str) -> None:
        if self.usage.calls >= self.settings.max_llm_calls:
            self.result.metrics.caps_hit.append("MAX_LLM_CALLS")
            self._record("TERMINATE", "LLM call budget exhausted")
            return
        payload = self._ask(task)
        proposals = self.proposals(task, payload)
        self.result.proposals_seen += len(proposals)
        self._record("OBSERVE", f"{len(proposals)} {task} proposal(s) from {self.client.name}")
        self._record("HYPOTHESIZE", "verifying each proposal against structured facts")
        for proposal in proposals:
            outcome = self._verify(task, proposal)
            if outcome is not None and outcome.accepted and outcome.capability is not None:
                self.result.capabilities.append(outcome.capability)
        self._record(
            "VERIFY",
            f"{len(self.result.capabilities)} agentic capability claim(s) accepted so far",
        )

    @staticmethod
    def proposals(task: str, payload: object) -> list[dict[str, Any]]:
        """Extract proposal objects from a model payload, ignoring malformed shapes."""
        if not isinstance(payload, dict):
            return []
        key = {"semantics": "interpretations", "composition": "chains", "stateful": "stateful"}[
            task
        ]
        raw = payload.get(key, [])
        if not isinstance(raw, list):
            return []
        return [item for item in raw if isinstance(item, dict)]

    def _verify(self, task: str, proposal: dict[str, Any]) -> VerificationOutcome | None:
        """Translate a proposal into a verifier call, recording malformed ones as rejected."""
        try:
            if task == "semantics":
                return self._verify_semantics(proposal)
            if task == "composition":
                return self._verify_composition(proposal)
            return self._verify_stateful(proposal)
        except (TypeError, ValueError) as error:  # pragma: no cover - defensive
            self.result.rejected_claims.append(
                RejectedClaim(claim=str(proposal)[:120], reason=f"malformed_proposal:{error}")
            )
            return None

    def _verify_semantics(self, proposal: dict[str, Any]) -> VerificationOutcome | None:
        tool_id = str(proposal.get("tool_id", ""))
        actions = proposal.get("extra_actions", [])
        if not isinstance(actions, list):
            actions = []
        outcomes: list[VerificationOutcome] = []
        for action in actions:
            for target in self._tool_targets(tool_id):
                for credential_id in self._obtainable_credentials():
                    outcomes.append(
                        self.verifier.verify_capability_claim(
                            action=str(action),
                            target=target,
                            tool_id=tool_id,
                            credential_id=credential_id,
                            state_depth=1,
                            span=proposal.get("span"),
                            summary=str(proposal.get("reason", "")),
                        )
                    )
        if not outcomes:
            return None
        return next((item for item in outcomes if item.accepted), outcomes[0])

    def _verify_composition(self, proposal: dict[str, Any]) -> VerificationOutcome:
        hops = [hop for hop in proposal.get("hops", []) if isinstance(hop, str)]
        tool_id = next((hop for hop in reversed(hops) if hop.startswith("tool-")), "")
        return self.verifier.verify_capability_claim(
            action=str(proposal.get("action", "")),
            target=str(proposal.get("target", "")),
            tool_id=tool_id,
            credential_id=str(proposal.get("credential_id", "")),
            state_depth=int(proposal.get("state_depth", 1) or 1),
            span=proposal.get("span"),
            summary=str(proposal.get("summary", "")),
        )

    def _verify_stateful(self, proposal: dict[str, Any]) -> VerificationOutcome:
        step = proposal.get("discovery_step") or {}
        return self.verifier.verify_capability_claim(
            action=str(proposal.get("action", "")),
            target=str(proposal.get("target", "")),
            tool_id=self._stateful_actor(),
            credential_id=str(proposal.get("credential_id", "")),
            state_depth=int(proposal.get("state_depth", 1) or 1),
            summary=str(proposal.get("summary", "")),
            discovery_step=(str(step.get("tool_id", "")), str(step.get("reveals", ""))),
        )

    # --- helpers ------------------------------------------------------------------------
    def _tool_targets(self, tool_id: str) -> list[str]:
        tool = self.verifier.tools.get(tool_id)
        if tool is None:
            return []
        if tool.targets:
            return list(tool.targets)
        return [resource.id for resource in self.analysis_input.resources]

    def _obtainable_credentials(self) -> list[str]:
        return [status.id for status in self.credentials if status.usable]

    def _stateful_actor(self) -> str:
        """The state-gated tool that can act on a discovered endpoint (any qualifies as actor)."""
        for tool in self.analysis_input.tools:
            gated = any(
                precondition.kind.value == "session_fact" for precondition in tool.preconditions
            )
            if gated and not tool.target_selector.closed_vocabulary:
                return tool.id
        return ""

    # --- entry point --------------------------------------------------------------------
    def run(self) -> AgenticResult:
        for task in MODE_TASKS[self.mode]:
            self._run_task(task)
        for pattern in sorted(set(self.verifier.injection_flags)):
            self.result.injection_attempts.append(
                InjectionAttempt(
                    source_ref="agentic_proposal",
                    pattern=pattern,
                    handling="proposal_checked_against_structured_facts_only",
                )
            )
        self.result.rejected_claims.extend(self.verifier.rejections)
        self.result.metrics.llm_calls = self.usage.calls
        self.result.metrics.input_tokens = self.usage.input_tokens
        self.result.metrics.output_tokens = self.usage.output_tokens
        self.result.metrics.estimated_cost_usd = self.usage.cost_usd
        self.result.metrics.tool_calls = self.result.proposals_seen
        if self._fallback is not None:
            # Self-describing degradation: a run that fell back must say so in the report itself.
            self.result.metrics.caps_hit.append("MODEL_UNAVAILABLE_FALLBACK")
            self._record(
                "DEGRADE",
                "the configured model was unavailable; the deterministic stand-in answered instead",
            )
        # The report must be able to resolve every evidence id a capability cites, including the
        # hypothesis items the verifier added, so the whole evidence space is carried across.
        self.result.evidence = list(self.ledger.items())
        self._record(
            "CONCLUDE",
            f"agentic layer finished with {self.client.name}: "
            f"{len(self.result.capabilities)} verified, "
            f"{len(self.result.rejected_claims)} rejected",
        )
        return self.result


def merge_agentic(baseline: AnalysisReport, result: AgenticResult) -> AnalysisReport:
    """Merge verified agentic capabilities into the baseline report.

    A capability the deterministic engine already found is *upgraded* (provenance and evidence are
    unioned, ``discovered_by`` becomes ``deterministic+agentic``) rather than duplicated, so the
    report never double-counts the same risk.
    """
    by_triple = {
        (item.action.value, item.target, item.environment): item for item in baseline.capabilities
    }
    capabilities = list(baseline.capabilities)
    for candidate in result.capabilities:
        key = (candidate.action.value, candidate.target, candidate.environment)
        existing = by_triple.get(key)
        if existing is None:
            by_triple[key] = candidate
            capabilities.append(candidate)
            continue
        upgraded = existing.model_copy(
            update={
                "evidence": sorted({*existing.evidence, *candidate.evidence}),
                "provenance": sorted({*existing.provenance, *candidate.provenance}),
                "discovered_by": "deterministic+agentic",
                "severity": (
                    candidate.severity
                    if severity_rank(candidate.severity) > severity_rank(existing.severity)
                    else existing.severity
                ),
                "state_depth": min(existing.state_depth, candidate.state_depth),
            }
        )
        by_triple[key] = upgraded
        capabilities[capabilities.index(existing)] = upgraded
    evidence_by_id = {item.id: item for item in baseline.evidence}
    for item in result.evidence:
        evidence_by_id.setdefault(item.id, item)
    return baseline.model_copy(
        update={
            "capabilities": sorted(capabilities, key=lambda item: (item.action.value, item.target)),
            "agent_rejected_claims": result.rejected_claims,
            "trajectory": result.trajectory,
            "metrics": result.metrics,
            "evidence": [evidence_by_id[key] for key in sorted(evidence_by_id)],
            "injection_attempts": [*baseline.injection_attempts, *result.injection_attempts],
        }
    )
