"""Blast-radius assembly: turn the closure result into the reported layers, findings, and summary.

This module is the bridge between "what the engine derived" and "what a reader is shown", and it is
where the declared / reachable / effective distinction becomes visible in the output.
"""

from __future__ import annotations

from app.analyzers.closure import ClosureResult
from app.analyzers.evidence import EvidenceLedger
from app.analyzers.reachability import ReachabilityAnalyzer
from app.analyzers.taxonomy import AUTHORITY_CLAIM_PATTERN
from app.graph.builder import EnvironmentGraph
from app.schemas.analysis import (
    AnalysisInput,
    AnalysisReport,
    Capability,
    Contradiction,
    Finding,
    InjectionAttempt,
    LayerComparison,
    LayerSummary,
    RiskSummary,
    RunMetrics,
)
from app.schemas.common import (
    ActionClass,
    Confidence,
    EvidenceKind,
    Recoverability,
    RunMode,
    Severity,
    VerificationStatus,
    max_severity,
    severity_rank,
    weakest_status,
)
from app.security.injection import scan_untrusted_texts
from app.utils.ids import make_id


def resource_label(environment: EnvironmentGraph, resource_id: str) -> str:
    resource = environment.resource(resource_id)
    return resource.name if resource is not None else resource_id


def build_injection_attempts(analysis_input: AnalysisInput) -> list[InjectionAttempt]:
    """Scan every piece of untrusted prose for injection signals (reporting, never enforcement)."""
    return scan_untrusted_texts(analysis_input.untrusted_texts())


def misleading_metadata_contradictions(
    analysis_input: AnalysisInput, environment: EnvironmentGraph, ledger: EvidenceLedger
) -> list[Contradiction]:
    """Detect prose that claims authority the structured data does not support.

    A tool that advertises "full administrator access" is not wrong to *say*; it is wrong to be
    believed. The report states the claim and the structured reality side by side.
    """
    contradictions: list[Contradiction] = []
    for tool in analysis_input.tools:
        text = tool.description_untrusted or ""
        if not text or not AUTHORITY_CLAIM_PATTERN.search(text):
            continue
        evidence = [item.id for item in ledger.items() if item.subject == tool.id]
        contradictions.append(
            Contradiction(
                id=make_id("contradiction", "MISLEADING_METADATA", tool.id),
                code="MISLEADING_METADATA",
                subject=tool.id,
                message=(
                    f"{tool.id} ({tool.name}) claims elevated authority in its untrusted metadata, "
                    f"while its structured declaration exposes only "
                    f"{', '.join(sorted(action.value for action in tool.actions)) or 'no actions'}. "
                    "The structured declaration governs."
                ),
                sides={"metadata": evidence[:1], "structured": evidence},
                evidence=evidence,
                severity_impact="claim_rejected",
            )
        )
    return contradictions


def build_finding(
    ledger: EvidenceLedger,
    environment: EnvironmentGraph,
    capability: Capability,
    *,
    min_facts_for_high: int = 2,
) -> Finding:
    """Promote a capability to a finding, applying the evidence gate for high impact."""
    counts = ledger.count_kinds(capability.evidence)
    status = capability.verification_status
    uncertainties = list(capability.uncertainties)

    if (
        capability.severity in {Severity.HIGH, Severity.CRITICAL}
        and counts["fact"] < min_facts_for_high
    ):
        status = weakest_status(status, VerificationStatus.POSSIBLE)
        uncertainties.append("insufficient_evidence")

    label = resource_label(environment, capability.target)
    environment_suffix = f" in {capability.environment}" if capability.environment else ""
    title = f"{capability.action.value} {label}{environment_suffix}"
    reason_parts = [
        (
            f"Agent {environment.analysis_input.agent.id} can perform {capability.action.value} on "
            f"{label}{environment_suffix}."
        )
    ]
    if len(capability.path) > 2:
        tool_id = capability.path[2]
        credential_id = capability.path[4] if len(capability.path) > 4 else None
        reason_parts.append(f"Via tool {tool_id}")
        if credential_id:
            reason_parts.append(f"using credential {credential_id}")
    reason_parts.append(f"reachability: {capability.reachability.render()}")
    if capability.blockers:
        reason_parts.append("controls in force: " + ", ".join(capability.blockers))
    if capability.derived_from:
        reason_parts.append("derived from " + ", ".join(capability.derived_from))

    return Finding(
        id=make_id("finding", capability.id),
        capability_id=capability.id,
        title=title,
        severity=capability.severity,
        severity_basis=capability.severity_basis,
        action=capability.action,
        target=capability.target,
        environment=capability.environment,
        recovery={
            "recoverability": capability.recoverability.value,
            "mechanisms": list(capability.recovery_mechanisms),
        },
        evidence=capability.evidence,
        evidence_count=counts,
        confidence=Confidence(
            value=capability.confidence,
            facts=counts["fact"],
            inferences=counts["inference"],
            hypotheses=counts["hypothesis"],
            basis=list(capability.severity_basis),
        ),
        verification_status=status,
        uncertainties=sorted(set(uncertainties)),
        discovered_by=capability.discovered_by,
        state_depth=capability.state_depth,
        reason=" ".join(reason_parts),
    )


def build_layers(closure: ClosureResult) -> LayerComparison:
    """Compare L0 declared, L1 reachable, and L2 effective authority without collapsing them."""
    capabilities = closure.capabilities
    effective_triples = {
        (item.action.value, item.target, item.environment) for item in capabilities
    }
    # The closure records these pairs with the ActionClass enum; `effective_triples` uses the plain
    # string value. ActionClass is a StrEnum, so the two compare equal at runtime, but mixing them
    # makes the type of every downstream lookup depend on which set it came from. Normalising once
    # here means the rest of the function has a single, obvious representation.
    declared = {(action.value, target, env) for action, target, env in closure.declared_pairs}
    reachable = {(action.value, target, env) for action, target, env in closure.reachable_pairs}

    def summarise(triples: set[tuple[str, str, str | None]]) -> LayerSummary:
        matching = [
            item
            for item in capabilities
            if (item.action.value, item.target, item.environment) in triples
        ]
        return LayerSummary(
            capabilities=len(triples),
            severity_max=max_severity(*[item.severity for item in matching])
            if matching
            else Severity.INFO,
            resource_count=len({target for _action, target, _env in triples}),
        )

    delta_notes: list[str] = []
    declared_only = sorted(declared - reachable)
    if declared_only:
        delta_notes.append(
            f"{len(declared_only)} declared capabilities are not reachable and are not reported as "
            "effective"
        )
    emergent = sorted(effective_triples - declared)
    if emergent:
        delta_notes.append(
            f"{len(emergent)} effective capabilities were never declared by policy "
            "(emerged from tool semantics, composition, or state growth)"
        )
    unreachable_declared = sorted(declared - effective_triples)
    if unreachable_declared:
        delta_notes.append(
            f"{len(unreachable_declared)} declared capabilities are not effective; see contradictions"
        )

    return LayerComparison(
        declared_authority=summarise(declared),
        reachable_authority=summarise(reachable),
        effective_capability=summarise(effective_triples),
        delta_notes=delta_notes,
    )


def rebuild_findings(report: AnalysisReport, *, min_facts_for_high: int = 2) -> AnalysisReport:
    """Rebuild the finding list from the *final* capability set.

    Needed after the agentic layer merges: a new capability must arrive with the same evidence-backed
    finding wrapper as a deterministic one, or the report would show risks without findings.
    """
    by_id = {item.id: item for item in report.evidence}
    findings: list[Finding] = []
    for capability in report.capabilities:
        items = [by_id[evidence_id] for evidence_id in capability.evidence if evidence_id in by_id]
        counts = {kind.value: 0 for kind in EvidenceKind}
        for item in items:
            counts[item.kind.value] += 1
        status = capability.verification_status
        uncertainties = list(capability.uncertainties)
        if (
            capability.severity in {Severity.HIGH, Severity.CRITICAL}
            and counts[EvidenceKind.FACT.value] < min_facts_for_high
        ):
            status = weakest_status(status, VerificationStatus.POSSIBLE)
            uncertainties.append("insufficient_evidence")
        label = capability.target
        environment_suffix = f" in {capability.environment}" if capability.environment else ""
        reason = (
            f"Agent {report.agent.id} can perform {capability.action.value} on "
            f"{label}{environment_suffix}."
        )
        if len(capability.path) > 2:
            credential_id = capability.path[4] if len(capability.path) > 4 else None
            reason += f" Via tool {capability.path[2]}"
            reason += f" using credential {credential_id}" if credential_id else ""
        reason += f" reachability: {capability.reachability.render()}"
        if capability.blockers:
            reason += " controls in force: " + ", ".join(capability.blockers)
        if capability.derived_from:
            reason += " derived from " + ", ".join(capability.derived_from)
        findings.append(
            Finding(
                id=make_id("finding", capability.id),
                capability_id=capability.id,
                title=f"{capability.action.value} {label}{environment_suffix}",
                severity=capability.severity,
                severity_basis=capability.severity_basis,
                action=capability.action,
                target=capability.target,
                environment=capability.environment,
                recovery={
                    "recoverability": capability.recoverability.value,
                    "mechanisms": list(capability.recovery_mechanisms),
                },
                evidence=capability.evidence,
                evidence_count=counts,
                confidence=Confidence(
                    value=capability.confidence,
                    facts=counts[EvidenceKind.FACT.value],
                    inferences=counts[EvidenceKind.INFERENCE.value],
                    hypotheses=counts[EvidenceKind.HYPOTHESIS.value],
                    basis=list(capability.severity_basis),
                ),
                verification_status=status,
                uncertainties=sorted(set(uncertainties)),
                discovered_by=capability.discovered_by,
                state_depth=capability.state_depth,
                reason=reason,
            )
        )
    return report.model_copy(
        update={
            "findings": sorted(
                findings, key=lambda item: (-severity_rank(item.severity), item.target)
            )
        }
    )


def with_recomputed_summary(report: AnalysisReport) -> AnalysisReport:
    """Recompute the headline risk numbers from the *final* capability set.

    Required after the agentic layer merges: a summary computed from the pre-merge capabilities
    would understate the very risks the agentic layer exists to find.
    """
    from app.schemas.analysis import RiskSummary

    capabilities = report.capabilities
    severities = [item.severity for item in capabilities]
    worst = (
        max(capabilities, key=lambda item: (severity_rank(item.severity), item.target))
        if capabilities
        else None
    )
    destructive = [
        item
        for item in capabilities
        if item.action
        in {ActionClass.DELETE, ActionClass.DESTROY, ActionClass.EXECUTE, ActionClass.ROTATE}
    ]
    irreversible = [
        item
        for item in capabilities
        if item.recoverability == Recoverability.POTENTIALLY_IRREVERSIBLE
    ]
    summary = RiskSummary(
        overall_severity=max_severity(*severities) if severities else Severity.INFO,
        highest_path=list(worst.path) if worst else [],
        capability_count=len(capabilities),
        direct_capabilities=sum(1 for item in capabilities if item.state_depth == 0),
        indirect_capabilities=sum(1 for item in capabilities if item.state_depth >= 1),
        cross_environment_paths=sum(1 for item in capabilities if item.cross_environment),
        destructive_capabilities=len(destructive),
        irreversible_capabilities=len(irreversible),
        contradiction_count=len(report.contradictions),
        uncertainty_count=len(report.uncertainties),
        rejected_claims=len(report.agent_rejected_claims),
    )
    # pydantic types model_copy as returning Self, which already narrows to the declared type here.
    # An earlier version wrapped this in a cast() on the assumption that model_copy returned Any; a
    # strict check reported the cast as redundant, so it was removed rather than suppressed.
    return report.model_copy(update={"risk_summary": summary})


def build_risk_summary(
    closure: ClosureResult,
    findings: list[Finding],
    injection_attempts: list[InjectionAttempt],
) -> RiskSummary:
    """Headline numbers, computed from the same objects the detailed report renders."""
    capabilities = closure.capabilities
    severities = [item.severity for item in capabilities]
    overall = max_severity(*severities) if severities else Severity.INFO
    worst = max(
        capabilities,
        key=lambda item: (severity_rank(item.severity), item.target),
        default=None,
    )
    destructive = [
        item
        for item in capabilities
        if item.action
        in {ActionClass.DELETE, ActionClass.DESTROY, ActionClass.EXECUTE, ActionClass.ROTATE}
    ]
    irreversible = [
        item
        for item in capabilities
        if item.recoverability == Recoverability.POTENTIALLY_IRREVERSIBLE
    ]
    return RiskSummary(
        overall_severity=overall,
        highest_path=list(worst.path) if worst else [],
        capability_count=len(capabilities),
        direct_capabilities=sum(1 for item in capabilities if item.state_depth == 0),
        indirect_capabilities=sum(1 for item in capabilities if item.state_depth >= 1),
        cross_environment_paths=sum(1 for item in capabilities if item.cross_environment),
        destructive_capabilities=len(destructive),
        irreversible_capabilities=len(irreversible),
        contradiction_count=len(closure.contradictions),
        uncertainty_count=len(closure.uncertainties),
        rejected_claims=0,
    )


def build_paths(closure: ClosureResult) -> tuple[list[list[str]], list[list[str]]]:
    """Split capability paths into confirmed (strong evidence) and potential (weaker) sets."""
    confirmed = [
        list(item.path)
        for item in sorted(closure.capabilities, key=lambda entry: entry.id)
        if item.verification_status == VerificationStatus.CONFIRMED
    ]
    potential = [
        list(item.path)
        for item in sorted(closure.capabilities, key=lambda entry: entry.id)
        if item.verification_status != VerificationStatus.CONFIRMED
    ]
    return confirmed, potential


def assemble_report(
    analysis_input: AnalysisInput,
    environment: EnvironmentGraph,
    reachability: ReachabilityAnalyzer,
    ledger: EvidenceLedger,
    closure: ClosureResult,
    *,
    analysis_id: str,
    run_mode: RunMode,
    min_facts_for_high: int = 2,
) -> AnalysisReport:
    """Build the full report object from the deterministic closure."""
    injection_attempts = build_injection_attempts(analysis_input)
    contradictions = [
        *closure.contradictions,
        *misleading_metadata_contradictions(analysis_input, environment, ledger),
    ]
    findings = [
        build_finding(ledger, environment, capability, min_facts_for_high=min_facts_for_high)
        for capability in sorted(closure.capabilities, key=lambda item: item.id)
    ]
    confirmed_paths, potential_paths = build_paths(closure)
    layers = build_layers(closure)
    summary = build_risk_summary(closure, findings, injection_attempts)
    summary.uncertainty_count = len(closure.uncertainties)

    return AnalysisReport(
        analysis_id=analysis_id,
        run_mode=run_mode,
        termination_reason="analysis_complete",
        agent=analysis_input.agent,
        identity=analysis_input.identity,
        environment=analysis_input.environment,
        layers=layers,
        risk_summary=summary,
        capabilities=closure.capabilities,
        findings=findings,
        confirmed_paths=confirmed_paths,
        potential_paths=potential_paths,
        contradictions=contradictions,
        uncertainties=closure.uncertainties,
        injection_attempts=injection_attempts,
        evidence=ledger.items(),
        scenario_id=analysis_input.scenario_id,
        metrics=RunMetrics(caps_hit=list(closure.caps_hit)),
    )
