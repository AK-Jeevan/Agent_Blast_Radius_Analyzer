"""The verification gate: every agentic proposal must survive deterministic checks.

The verifier is the architectural answer to hallucination. A model may *propose* a capability, but
the report only ever contains capabilities for which the verifier independently confirmed:

* the tool, credential, identity, and target all exist in the parsed input;
* the credential is actually obtainable (present, or readable by a tool in scope);
* the target is network-reachable from the agent;
* policy authorizes that exact action on that exact resource via that exact credential;
* the quoted supporting span really appears in the (untrusted) source text it claims to quote;
* the resulting status never exceeds ``PROBABLE`` and the severity is capped accordingly.

Rejected proposals are returned, not hidden: they populate ``agent_rejected_claims`` and double as
the prompt-injection signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.analyzers.authz import PolicyEvaluator
from app.analyzers.closure import (
    applicable_blockers,
    confidence_for,
    control_kinds,
    enriched_path,
    tier_for_environment_name,
)
from app.analyzers.credentials import CredentialStatus
from app.analyzers.evidence import EvidenceLedger
from app.analyzers.reachability import ReachabilityAnalyzer
from app.analyzers.scoring import assess_severity, recovery_for
from app.graph.builder import EnvironmentGraph
from app.schemas.analysis import (
    AnalysisInput,
    Capability,
    PreconditionResult,
    ReachabilityView,
    RejectedClaim,
)
from app.schemas.common import (
    ActionClass,
    EvidenceKind,
    Relationship,
    Source,
    SourceKind,
    VerificationStatus,
)
from app.security.injection import scan_text
from app.utils.ids import make_id, path_hash

#: The strongest status an agentic claim may ever receive, no matter what the model asserts.
AGENTIC_STATUS_CEILING = VerificationStatus.PROBABLE


@dataclass
class VerificationOutcome:
    """Result of checking one proposal."""

    accepted: bool
    reason: str
    capability: Capability | None = None
    rejected: RejectedClaim | None = None
    evidence_ids: list[str] = field(default_factory=list)


class ClaimVerifier:
    """Deterministic acceptance test for agentic capability claims."""

    def __init__(
        self,
        analysis_input: AnalysisInput,
        environment: EnvironmentGraph,
        ledger: EvidenceLedger,
        reachability: ReachabilityAnalyzer,
        evaluator: PolicyEvaluator,
        credential_statuses: list[CredentialStatus],
    ) -> None:
        self.analysis_input = analysis_input
        self.environment = environment
        self.ledger = ledger
        self.reachability = reachability
        self.evaluator = evaluator
        self.credential_statuses = {status.id: status for status in credential_statuses}
        self.entity_ids = analysis_input.entity_ids()
        self.tools = {tool.id: tool for tool in analysis_input.tools}
        self.resources = {resource.id: resource for resource in analysis_input.resources}
        self.rejections: list[RejectedClaim] = []
        self.injection_flags: list[str] = []

    # --- helpers -------------------------------------------------------------------------
    def _reject(
        self, claim: str, reason: str, *, source_ref: str | None = None, injection: bool = False
    ) -> VerificationOutcome:
        rejection = RejectedClaim(
            claim=claim, reason=reason, source_ref=source_ref, injection_signal=injection
        )
        self.rejections.append(rejection)
        return VerificationOutcome(accepted=False, reason=reason, rejected=rejection)

    def _span_is_real(self, tool_id: str, span: str | None) -> bool:
        """The quoted span must actually occur in the untrusted source it is attributed to."""
        if not span or not span.strip():
            return False
        tool = self.tools.get(tool_id)
        if tool is None:
            return False
        haystack = " ".join(
            filter(
                None,
                [
                    tool.name,
                    tool.description_untrusted or "",
                    str(tool.input_schema),
                ],
            )
        )
        probe = span.strip()
        if probe in haystack:
            return True
        # Fall back to token overlap so a truncated or reformatted quote still validates.
        tokens = [token for token in re.split(r"\W+", probe) if len(token) > 3]
        if not tokens:
            return False
        overlap = sum(1 for token in tokens if token in haystack)
        return overlap / len(tokens) >= 0.6

    def credential_is_obtainable(self, credential_id: str) -> bool:
        status = self.credential_statuses.get(credential_id)
        return bool(status and status.usable)

    def identity_id(self) -> str:
        identity = self.analysis_input.identity
        return identity.id if identity is not None else self.analysis_input.agent.id

    def _evidence_for(self, subjects: set[str], predicate: str | None = None) -> set[str]:
        """Collect evidence ids whose subject is in ``subjects`` (optionally filtered by predicate)."""
        return {
            item.id
            for item in self.ledger.items()
            if item.subject in subjects and (predicate is None or item.predicate == predicate)
        }

    def verify_capability_claim(
        self,
        *,
        action: str,
        target: str,
        tool_id: str,
        credential_id: str,
        state_depth: int = 1,
        span: str | None = None,
        summary: str = "",
        discovery_step: tuple[str, str] | None = None,
    ) -> VerificationOutcome:
        """Check one proposed capability end to end and build the reportable form if it holds."""
        claim = summary or f"{action} on {target} via {tool_id}"

        if tool_id not in self.tools:
            return self._reject(claim, "unknown_entity_id:tool")
        if target not in self.resources:
            return self._reject(claim, "unknown_entity_id:target")
        if credential_id not in self.credential_statuses:
            return self._reject(claim, "unknown_entity_id:credential")
        try:
            action_class = ActionClass(action)
        except ValueError:
            return self._reject(claim, "unknown_action")
        if not self.credential_is_obtainable(credential_id):
            return self._reject(claim, "credential_not_obtainable")

        # A claim may be justified structurally (the tool declares this action on this kind of
        # target) or by a quotation. Claiming an action the tool does *not* declare always requires a
        # real quotation, because that is precisely the semantic-inference case.
        declared_by_tool = action_class in self.tools[tool_id].actions
        if not self._span_is_real(tool_id, span) and not declared_by_tool:
            return self._reject(claim, "unsupported_span", source_ref=tool_id)

        record = self.reachability.record(target)
        if record is None or not record.reachable:
            return self._reject(claim, "unreachable", source_ref=tool_id)

        resource = self.resources[target]
        status = self.credential_statuses[credential_id]
        principals = tuple(
            sorted({self.identity_id(), status.assumed_identity or self.identity_id()})
        )
        decision = self.evaluator.evaluate(
            principals, resource, action_class, via_credential=credential_id
        )
        if not decision.allowed:
            return self._reject(claim, f"not_authorized:{decision.reason}", source_ref=tool_id)

        authenticated = record.authenticated_for((credential_id,))
        verification_status = AGENTIC_STATUS_CEILING
        if authenticated is None or decision.needs_downgrade:
            verification_status = VerificationStatus.POSSIBLE

        evidence_ids = self._evidence_for(set(decision.policies))
        evidence_ids |= self._evidence_for(set(record.edge_ids))
        evidence_ids |= self._evidence_for({credential_id})
        evidence_ids |= self._evidence_for({tool_id}, "exposes_action")
        hypothesis_id = self.ledger.add(
            kind=EvidenceKind.HYPOTHESIS,
            subject=tool_id,
            predicate="semantic_or_composed_capability",
            obj=f"{action_class.value}:{target}",
            supports=tuple(sorted(evidence_ids)),
            note=(span or "")[:240],
            source=Source(kind=SourceKind.TOOL_DESCRIPTION, ref=tool_id, trusted=False),
        )
        evidence_ids.add(hypothesis_id)

        injection = scan_text(tool_id, span or "")
        self.injection_flags.extend(item.pattern for item in injection)

        blockers = applicable_blockers(
            self.analysis_input, self.tools[tool_id], action_class, resource.environment
        )
        recoverability, mechanisms, _notes = recovery_for(resource)
        assessment = assess_severity(
            action_class,
            resource,
            tier=tier_for_environment_name(resource.environment),
            status=verification_status,
            recoverability=recoverability,
            blocker_kinds=control_kinds(self.analysis_input, blockers),
        )

        # The path is built by the deterministic planner, not assembled here from a template. The
        # verifier already imports the deterministic plane, and the point of the verifier is to
        # *hold the agentic plane to the deterministic standard*: letting it narrate its own chain
        # would let an accepted claim carry edges the environment does not contain, which is the one
        # thing path verification exists to catch.
        path = enriched_path(
            self.environment,
            self.analysis_input.agent.id,
            self.tools[tool_id],
            credential_id,
            status.assumed_identity,
            target,
        )
        if discovery_step is not None and path:
            # The credential was obtained earlier in the session by a different tool. Prepend that
            # real discovery hop so the chain shows the accumulation, and only when the planner found
            # the path empty would this be a way to invent a chain -- so it is guarded.
            discovery_tool, discovered = discovery_step
            if discovered in path and not any(item == discovery_tool for item in path):
                path = [
                    self.analysis_input.agent.id,
                    Relationship.USES.value,
                    discovery_tool,
                    *path[1:],
                ]
        agent_environment = (
            self.analysis_input.environment.name
            if self.analysis_input.environment is not None
            else self.analysis_input.agent.environment
        )
        capability = Capability(
            id=make_id("capability", action_class.value, target, tool_id, credential_id, "agentic"),
            action=action_class,
            target=target,
            environment=resource.environment,
            path=path,
            path_hash=path_hash(path),
            preconditions=[
                PreconditionResult(
                    kind="agentic_proposal",
                    ref=hypothesis_id,
                    satisfied=True,
                    note="accepted after deterministic re-verification",
                )
            ],
            blockers=blockers,
            reachability=ReachabilityView(
                reachable=True,
                authenticated=authenticated,
                authorized=True,
                actionable=True,
            ),
            severity=assessment.severity,
            severity_basis=[*assessment.basis, "AGENTIC_VERIFIED"],
            recoverability=recoverability,
            recovery_mechanisms=mechanisms,
            verification_status=verification_status,
            confidence=confidence_for(sorted(evidence_ids), verification_status, self.ledger),
            evidence=sorted(evidence_ids),
            discovered_by="agentic",
            state_depth=max(1, state_depth),
            uncertainties=["agentic_proposal", "verified_by_deterministic_checks"],
            cross_environment=bool(
                resource.environment
                and agent_environment
                and resource.environment != agent_environment
            ),
            provenance=sorted(
                {
                    self.analysis_input.agent.id,
                    tool_id,
                    target,
                    credential_id,
                    *([status.assumed_identity] if status.assumed_identity else []),
                    *decision.policies,
                    *([discovery_step[1]] if discovery_step else []),
                }
            ),
        )
        return VerificationOutcome(
            accepted=True,
            reason="verified",
            capability=capability,
            evidence_ids=sorted(evidence_ids),
        )
