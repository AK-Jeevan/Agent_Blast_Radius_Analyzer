"""Counterfactual analysis (master prompt §27): a graph edit plus a full deterministic re-run.

A counterfactual is never a narrative guess. Each operation edits a *copy* of the parsed facts, the
deterministic engine is re-run on that copy, and the two capability sets are diffed. If an edit that
should reduce authority instead *adds* capabilities, the result is flagged ``non_monotone_edit``
rather than being quietly accepted.

Nothing here modifies the analysed environment: it is analysis only (human-in-the-loop, §28).
"""

from __future__ import annotations

from app.analyzers.engine import run_deterministic
from app.config import Settings
from app.schemas.analysis import (
    AnalysisInput,
    AnalysisReport,
    Capability,
    CounterfactualOp,
    CounterfactualResult,
)
from app.schemas.common import ActionClass, Severity, max_severity, severity_rank
from app.schemas.entities import NetworkEdge

#: Actions worth reducing first, ordered by blast-radius impact.
DESTRUCTIVE_VERBS = (
    ActionClass.DESTROY,
    ActionClass.DELETE,
    ActionClass.GRANT,
    ActionClass.EXECUTE,
    ActionClass.DEPLOY,
)


def apply_op(analysis_input: AnalysisInput, op: CounterfactualOp) -> AnalysisInput:
    """Return a modified copy of the input with the counterfactual edit applied."""

    def copy(**updates: object) -> AnalysisInput:
        return analysis_input.model_copy(update=updates)

    agent_environment = (
        analysis_input.environment.name if analysis_input.environment else None
    ) or analysis_input.agent.environment
    match op.kind:
        case "remove_tool":
            return copy(tools=[tool for tool in analysis_input.tools if tool.id != op.target_id])
        case "remove_mcp_server":
            return copy(tools=[tool for tool in analysis_input.tools if not tool.is_mcp])
        case "remove_credential":
            return copy(
                credentials=[
                    credential
                    for credential in analysis_input.credentials
                    if credential.id != op.target_id
                ]
            )
        case "reduce_scope":
            return copy(
                credentials=[
                    credential.model_copy(update={"scope": [agent_environment]})
                    if credential.id == op.target_id
                    else credential
                    for credential in analysis_input.credentials
                ]
            )
        case "remove_permission":
            return copy(
                permissions=[
                    permission
                    for permission in analysis_input.permissions
                    if permission.id != op.target_id
                ]
            )
        case "block_network_edge":
            return copy(
                network=[
                    edge.model_copy(update={"reachable": False})
                    if edge.id == op.target_id
                    else edge
                    for edge in analysis_input.network
                ]
            )
        case "separate_environment":
            return copy(
                network=[
                    edge
                    for edge in analysis_input.network
                    if not (
                        agent_environment
                        and edge.source.trusted
                        and _edge_targets_environment(edge, agent_environment)
                    )
                ]
            )
        case "add_blocker" | "add_dry_run":
            return copy(
                tools=[
                    tool.model_copy(update={"blockers": sorted({*tool.blockers, op.target_id})})
                    for tool in analysis_input.tools
                ]
            )
        case _:  # pragma: no cover - the Literal exhausts the set
            raise ValueError(f"unsupported counterfactual op: {op.kind}")


def _edge_targets_environment(edge: NetworkEdge, agent_environment: str) -> bool:
    """True when a network edge points at a resource in a different environment than the agent."""
    marker = edge.boundary or ""
    if agent_environment and marker.endswith(agent_environment):
        return False
    return bool(marker) and agent_environment not in marker


def _triples(report: AnalysisReport) -> dict[tuple[str, str], Capability]:
    """Index a report's capabilities by ``(action, target)``.

    The annotation says ``Capability``, not ``AnalysisReport``: the values are individual capability
    records, and the earlier wrong annotation let a type checker "correctly" reject the ``.severity`` and
    ``.id`` accesses in :func:`evaluate_counterfactual` that are in fact valid. A wrong annotation on a
    helper is not cosmetic -- it makes the caller's correct code look broken, and invites a "fix" that
    would break the engine.
    """
    return {(item.action.value, item.target): item for item in report.capabilities}


def evaluate_counterfactual(
    analysis_input: AnalysisInput, op: CounterfactualOp, baseline: AnalysisReport
) -> CounterfactualResult:
    """Apply the edit, re-run the deterministic engine, and diff the capability sets."""
    modified = apply_op(analysis_input, op)
    after = run_deterministic(modified)
    before_triples = _triples(baseline)
    after_triples = _triples(after)

    removed = [item.id for key, item in before_triples.items() if key not in after_triples]
    added = [item.id for key, item in after_triples.items() if key not in before_triples]
    downgraded = [
        item.id
        for key, item in before_triples.items()
        if key in after_triples
        and severity_rank(after_triples[key].severity) < severity_rank(item.severity)
    ]
    severity_before = max_severity(*[item.severity for item in before_triples.values()])
    severity_after = max_severity(*[item.severity for item in after_triples.values()])

    if removed:
        narrative = (
            f"{op.kind} {op.target_id} eliminates {len(removed)} capability(ies) and moves the worst "
            f"severity from {severity_before.value} to {severity_after.value}."
        )
    else:
        narrative = (
            f"{op.kind} {op.target_id} removes no capability on its own; worst severity "
            f"{severity_before.value} -> {severity_after.value}."
        )
    if added:
        narrative += " WARNING: the edit added capabilities, so it is not a pure reduction."

    return CounterfactualResult(
        op=op,
        capabilities_removed=sorted(removed),
        capabilities_downgraded=sorted(downgraded),
        capabilities_added=sorted(added),
        severity_before=severity_before,
        severity_after=severity_after,
        non_monotone_edit=bool(added),
        narrative=narrative,
    )


def suggest_ops(analysis_input: AnalysisInput, report: AnalysisReport) -> list[CounterfactualOp]:
    """Candidate controls, derived from the report's own evidence rather than guesswork."""
    candidates: list[CounterfactualOp] = []
    seen: set[str] = set()
    impactful = [
        item
        for item in report.capabilities
        if item.action in DESTRUCTIVE_VERBS
        and severity_rank(item.severity) >= severity_rank(Severity.MEDIUM)
    ]
    for item in impactful:
        tool_id = item.path[2] if len(item.path) > 2 else None
        credential_id = item.path[4] if len(item.path) > 4 else None
        if tool_id and tool_id not in seen:
            seen.add(tool_id)
            candidates.append(CounterfactualOp(kind="remove_tool", target_id=tool_id))
        if credential_id and credential_id not in seen:
            seen.add(credential_id)
            candidates.append(CounterfactualOp(kind="reduce_scope", target_id=credential_id))
        for edge in analysis_input.network:
            if edge.target == item.target and edge.reachable and edge.id not in seen:
                seen.add(edge.id)
                candidates.append(CounterfactualOp(kind="block_network_edge", target_id=edge.id))
    approval = next(
        (blocker for blocker in analysis_input.blockers if blocker.kind.value == "approval_gate"),
        None,
    )
    if approval is not None and approval.id not in seen:
        candidates.append(CounterfactualOp(kind="add_blocker", target_id=approval.id))
    return candidates


def counterfactual_suggestions(
    analysis_input: AnalysisInput,
    report: AnalysisReport,
    settings: Settings | None = None,
    *,
    max_ops: int = 3,
) -> list[CounterfactualResult]:
    """Rank control candidates by how much blast radius they remove, best first."""
    settings = settings or Settings()
    results = [
        evaluate_counterfactual(analysis_input, op, report)
        for op in suggest_ops(analysis_input, report)[: max_ops * 3]
    ]
    results.sort(
        key=lambda item: (len(item.capabilities_removed), severity_rank(item.severity_before)),
        reverse=True,
    )
    return results[:max_ops]
