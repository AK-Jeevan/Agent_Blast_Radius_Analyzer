"""Text rendering of a report, following the layout in the master prompt §18.

The text report and the JSON report are generated from the *same* object, so they cannot drift.
"""

from __future__ import annotations

from app.schemas.analysis import AnalysisReport, Capability, NarrativeStatement
from app.schemas.common import Severity, VerificationStatus, severity_rank

WIDTH = 80
SEPARATOR = "=" * WIDTH
THIN = "-" * WIDTH

_SEVERITY_MARK: dict[Severity, str] = {
    Severity.INFO: "-",
    Severity.LOW: "+",
    Severity.MEDIUM: "!",
    Severity.HIGH: "!!",
    Severity.CRITICAL: "!!!",
}

_STATUS_MARK: dict[VerificationStatus, str] = {
    VerificationStatus.CONFIRMED: "[confirmed]",
    VerificationStatus.PROBABLE: "[probable]",
    VerificationStatus.POSSIBLE: "[possible]",
    VerificationStatus.UNVERIFIED: "[unverified]",
    VerificationStatus.CONTRADICTED: "[contradicted]",
}


def path_lines(path: list[str]) -> list[str]:
    """Render a (entity, relationship, entity, ...) path as an indented chain."""
    lines: list[str] = []
    for index, item in enumerate(path):
        lines.append("  " * (1 if index == 0 else 2) + item)
    return lines


def _capability_block(capability: Capability, report: AnalysisReport) -> list[str]:
    mark = _SEVERITY_MARK[capability.severity]
    lines = [
        (
            f"  {mark} {capability.severity.value:<8} {capability.action.value} -> {capability.target} "
            f"({capability.environment or 'unknown env'}) {_STATUS_MARK[capability.verification_status]}"
        )
    ]
    lines.append(f"      reachability: {capability.reachability.render()}")
    if capability.blockers:
        lines.append(f"      controls    : {', '.join(capability.blockers)}")
    if capability.recovery_mechanisms:
        lines.append(
            f"      recovery    : {capability.recoverability.value} "
            f"({', '.join(capability.recovery_mechanisms)})"
        )
    return lines


def collect_narrative(report: AnalysisReport) -> list[NarrativeStatement]:
    """The report's explanatory sentences, each with the evidence ids that support it.

    These are the same sentences the renderer prints, so explanation faithfulness
    (docs/EVALUATION_PLAN.md §5) is measured on real content rather than on prose heuristics. Only
    sentences that *assert* something are included; headings, tables, and id lists are structure, not
    claims, and counting them would inflate the score with non-prose.
    """
    statements: list[NarrativeStatement] = []

    def add(text: str, evidence_ids: list[str] | None, kind: str = "explanation") -> None:
        if not text or not text.strip():
            return
        statements.append(
            NarrativeStatement(text=text.strip(), evidence_ids=list(evidence_ids or []), kind=kind)
        )

    overall = report.risk_summary.overall_severity
    headline_evidence = [item.id for item in report.evidence if item.kind == "inference"][:3]
    add(
        f"Overall blast radius is {overall.value} across {len(report.capabilities)} capabilities.",
        headline_evidence,
        kind="headline",
    )
    for capability in report.capabilities:
        basis = "; ".join(capability.severity_basis) or "no severity basis recorded"
        add(
            f"Agent {report.agent.id} can perform {capability.action.value} on "
            f"{capability.target} in {capability.environment or 'an unknown environment'} "
            f"({capability.reachability.render()}): {basis}.",
            list(capability.evidence),
            kind="capability",
        )
    for contradiction in report.contradictions:
        add(
            f"{contradiction.code} on {contradiction.subject}: {contradiction.message}",
            list(contradiction.evidence),
            kind="contradiction",
        )
    for counterfactual in report.counterfactuals:
        add(
            f"Counterfactual {counterfactual.op.kind}({counterfactual.op.target_id}) removes "
            f"{len(counterfactual.capabilities_removed)} capabilities and changes severity from "
            f"{counterfactual.severity_before.value} to {counterfactual.severity_after.value}.",
            list(counterfactual.capabilities_removed)[:3],
            kind="remediation",
        )
    for uncertainty in report.uncertainties:
        # `affects` names what the uncertainty weakens -- those are entity ids, not evidence ids, so
        # they must never be presented as citations. Where the report does carry evidence for the
        # subject, cite it; otherwise the sentence is honestly uncited and faithfulness will say so.
        about = [item for item in report.evidence if item.subject in set(uncertainty.affects)]
        add(
            f"Uncertainty {uncertainty.code}: {uncertainty.message}",
            [item.id for item in about],
            kind="explanation",
        )
    return statements


def finalise_report(report: AnalysisReport) -> AnalysisReport:
    """Attach the human-readable text and the machine-checkable narrative, in that order.

    One function, called last, so ``report_text`` and ``narrative`` can never describe different
    versions of the same report. The narrative is collected first because rendering needs nothing
    from it, while the evaluator needs both to agree.
    """
    report.narrative = collect_narrative(report)
    report.report_text = render_report(report)
    return report


def render_report(report: AnalysisReport) -> str:
    """Render the full blast-radius report as text."""
    out: list[str] = [SEPARATOR, "AGENT BLAST-RADIUS ANALYSIS", SEPARATOR]
    out.append(f"analysis_id : {report.analysis_id}")
    out.append(f"agent       : {report.agent.name} ({report.agent.id})")
    out.append(f"identity    : {report.identity.name if report.identity else 'unspecified'}")
    out.append(
        "environment : "
        + (
            f"{report.environment.name} (tier={report.environment.tier.value})"
            if report.environment
            else "unspecified"
        )
    )
    out.append(f"run mode    : {report.run_mode.value}")
    out.append(f"termination : {report.termination_reason}")
    out.append("")

    layers = report.layers
    out.append(THIN)
    out.append("AUTHORITY LAYERS (declared != reachable != effective)")
    out.append(THIN)
    out.append(
        f"L0 declared  : {layers.declared_authority.capabilities} capabilities, "
        f"max {layers.declared_authority.severity_max.value}"
    )
    out.append(
        f"L1 reachable : {layers.reachable_authority.capabilities} capabilities, "
        f"max {layers.reachable_authority.severity_max.value}"
    )
    out.append(
        f"L2 effective : {layers.effective_capability.capabilities} capabilities, "
        f"max {layers.effective_capability.severity_max.value}"
    )
    for note in layers.delta_notes:
        out.append(f"  delta: {note}")
    out.append("")

    out.append(THIN)
    out.append("DIRECT CAPABILITIES (no session state required)")
    out.append(THIN)
    direct = [item for item in report.capabilities if item.state_depth == 0]
    indirect = [item for item in report.capabilities if item.state_depth >= 1]
    if not direct:
        out.append("  (none)")
    for capability in direct:
        out.extend(_capability_block(capability, report))
    out.append("")

    out.append(THIN)
    out.append("INDIRECT / EMERGENT CAPABILITIES (require session state)")
    out.append(THIN)
    if not indirect:
        out.append("  (none)")
    for capability in indirect:
        out.extend(_capability_block(capability, report))
    out.append("")

    out.append(THIN)
    out.append("HIGH-IMPACT PATHS")
    out.append(THIN)
    high = [
        finding
        for finding in report.findings
        if severity_rank(finding.severity) >= severity_rank(Severity.HIGH)
    ]
    if not high:
        out.append("  (none)")
    for finding in high:
        # Named `related` rather than `capability`: the direct/indirect loops above already bind
        # `capability` as a non-optional Capability, and re-binding it to an optional type in the same
        # function scope makes the earlier usages look unsafe to a reader and to a type checker.
        related: Capability | None = next(
            (item for item in report.capabilities if item.id == finding.capability_id), None
        )
        out.append(
            f"  {_SEVERITY_MARK[finding.severity]} {finding.severity.value:<8} {finding.title} "
            f"{_STATUS_MARK[finding.verification_status]}"
        )
        out.append(f"    action        : {finding.action.value}")
        out.append(f"    target        : {finding.target}")
        out.append(f"    recoverability: {finding.recovery.get('recoverability')}")
        if finding.recovery.get("mechanisms"):
            out.append(f"    mechanisms    : {', '.join(finding.recovery['mechanisms'])}")
        if related is not None:
            out.append("    path:")
            out.extend(path_lines(related.path))
        out.append("")

    out.append(THIN)
    out.append("CONTRADICTIONS (declared vs effective)")
    out.append(THIN)
    if not report.contradictions:
        out.append("  (none)")
    for contradiction in report.contradictions:
        out.append(f"  [{contradiction.code}] {contradiction.subject}")
        out.append(f"    {contradiction.message}")
        out.append(f"    declared  : {', '.join(contradiction.sides.get('declared', [])) or 'n/a'}")
        out.append(
            f"    effective : {', '.join(contradiction.sides.get('effective', [])) or 'n/a'}"
        )
    out.append("")

    out.append(THIN)
    out.append("EVIDENCE AND CONFIDENCE")
    out.append(THIN)
    for finding in report.findings:
        counts = finding.evidence_count
        out.append(
            f"  {finding.id} {finding.title} -> {finding.severity.value} "
            f"confidence={finding.confidence.value:.2f} "
            f"(facts={counts.get('fact', 0)} inferences={counts.get('inference', 0)} "
            f"hypotheses={counts.get('hypothesis', 0)})"
        )
        out.append(f"    {finding.reason}")
    out.append("")

    out.append(THIN)
    out.append("UNCERTAINTIES")
    out.append(THIN)
    if not report.uncertainties:
        out.append("  (none)")
    seen: set[str] = set()
    for capability in report.capabilities:
        for code in capability.uncertainties:
            if code in seen:
                continue
            seen.add(code)
            out.append(f"  - {code} (affects {capability.action.value}->{capability.target})")
    for uncertainty in report.uncertainties:
        out.append(f"  - {uncertainty.code}: {uncertainty.message}")
    out.append("")

    if report.injection_attempts:
        out.append(THIN)
        out.append("UNTRUSTED CONTENT SIGNALS (data only, never instructions)")
        out.append(THIN)
        for attempt in report.injection_attempts:
            out.append(f"  - {attempt.source_ref}: {attempt.pattern} ({attempt.handling})")
        out.append("")

    if report.agent_rejected_claims:
        out.append(THIN)
        out.append("REJECTED AGENTIC CLAIMS")
        out.append(THIN)
        for rejected in report.agent_rejected_claims:
            out.append(f"  - [{rejected.reason}] {rejected.claim}")
        out.append("")

    if report.counterfactuals:
        out.append(THIN)
        out.append("COUNTERFACTUALS (analysis only, nothing was applied)")
        out.append(THIN)
        for result in report.counterfactuals:
            out.append(
                f"  - {result.op.kind} {result.op.target_id}: "
                f"{result.severity_before.value} -> {result.severity_after.value}, "
                f"{len(result.capabilities_removed)} capabilities removed"
            )
        out.append("")

    summary = report.risk_summary
    out.append(SEPARATOR)
    out.append(
        f"summary: {summary.overall_severity.value} | {summary.capability_count} capabilities | "
        f"{summary.direct_capabilities} direct / {summary.indirect_capabilities} state-dependent | "
        f"{summary.cross_environment_paths} cross-environment | "
        f"{summary.destructive_capabilities} destructive | "
        f"{summary.irreversible_capabilities} irreversible | "
        f"{summary.contradiction_count} contradictions | "
        f"{summary.uncertainty_count} uncertainties"
    )
    out.append(SEPARATOR)

    # The evidence ledger. Without it the report cites ids (in the narrative, in each capability, in
    # each contradiction) that a reader cannot resolve, which makes the whole document unverifiable by
    # hand. The project's claim is that every conclusion is traceable to evidence, so the evidence has
    # to be printed next to the conclusions.
    #
    # Citations are of two kinds and both must resolve: evidence ids (``ev-*``) and capability ids
    # (``cap-*``). Counterfactual statements cite the capabilities they claim to add or remove, which
    # is the meaningful thing to point at -- but those ids are not evidence items, so a ledger built
    # from ``report.evidence`` alone silently omitted them and the report ended up citing ids the
    # reader still could not look up. Only ids something actually cites are listed, so the appendix
    # does not drown the findings in facts nothing relies on.
    cited: set[str] = set()
    for statement in report.narrative:
        cited.update(statement.evidence_ids)
    for capability in report.capabilities:
        cited.update(capability.evidence)
    for contradiction in report.contradictions:
        cited.update(contradiction.evidence)
    ledger = [item for item in report.evidence if item.id in cited]
    cited_capabilities = [item for item in report.capabilities if item.id in cited]
    out.append(THIN)
    out.append(
        f"EVIDENCE LEDGER ({len(ledger)} of {len(report.evidence)} evidence items, "
        f"{len(cited_capabilities)} of {len(report.capabilities)} capabilities are cited)"
    )
    out.append(THIN)
    for item in ledger:
        out.append(f"  {item.id} [{item.kind.value}] {item.subject} {item.predicate} {item.object}")
        if item.note:
            out.append(f"      {item.note}")
    for capability in cited_capabilities:
        out.append(
            f"  {capability.id} [capability] {capability.action.value} -> {capability.target} "
            f"({capability.environment or 'unknown env'}, {capability.severity.value}, "
            f"{capability.verification_status.value})"
        )
    out.append(SEPARATOR)
    return "\n".join(out)
