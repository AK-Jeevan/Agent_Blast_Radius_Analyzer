"""Rendering helpers for the Gradio demo.

Kept separate from the UI assembly so each view is independently testable and the interface code
stays declarative. Every view is generated from the same report object the API returns.
"""

from __future__ import annotations

import json
from typing import Any

from app.schemas.analysis import AnalysisReport
from app.schemas.scenario import Scenario
from app.services.loader import scenario_expectation_summary


def overview_markdown(scenario: Scenario, report: AnalysisReport, notes: list[str]) -> str:
    """Headline view: overall severity plus the declared/reachable/effective comparison."""
    summary = report.risk_summary
    layers = report.layers
    lines = [
        f"## {scenario.title}",
        "",
        (
            f"**Overall severity: `{summary.overall_severity.value}`** &nbsp;|&nbsp; "
            f"agent `{report.agent.id}` &nbsp;|&nbsp; mode `{report.run_mode.value}`"
        ),
        "",
        "| layer | capabilities | max severity |",
        "|---|---|---|",
        (
            f"| L0 declared | {layers.declared_authority.capabilities} | "
            f"{layers.declared_authority.severity_max.value} |"
        ),
        (
            f"| L1 reachable | {layers.reachable_authority.capabilities} | "
            f"{layers.reachable_authority.severity_max.value} |"
        ),
        (
            f"| L2 effective | {layers.effective_capability.capabilities} | "
            f"{layers.effective_capability.severity_max.value} |"
        ),
        "",
        (
            f"- direct capabilities: **{summary.direct_capabilities}**, "
            f"state-dependent: **{summary.indirect_capabilities}**"
        ),
        (
            f"- cross-environment paths: **{summary.cross_environment_paths}**, "
            f"destructive: **{summary.destructive_capabilities}**, "
            f"irreversible: **{summary.irreversible_capabilities}**"
        ),
        (
            f"- contradictions: **{summary.contradiction_count}**, "
            f"uncertainties: **{summary.uncertainty_count}**, "
            f"rejected agentic claims: **{summary.rejected_claims}**"
        ),
    ]
    lines += [f"- _{note}_" for note in layers.delta_notes]
    lines += [f"- {note}" for note in notes]
    if summary.highest_path:
        lines += ["", "**Highest-severity path**", "", "```"]
        lines += summary.highest_path
        lines += ["```"]
    return "\n".join(lines)


def capability_rows(report: AnalysisReport) -> list[list[Any]]:
    return [
        [
            item.action.value,
            item.target,
            item.environment or "-",
            item.severity.value,
            item.verification_status.value,
            round(item.confidence, 2),
            item.state_depth,
            item.discovered_by,
            " -> ".join(item.path[1::2]),
        ]
        for item in report.capabilities
    ]


def finding_rows(report: AnalysisReport) -> list[list[Any]]:
    return [
        [
            item.severity.value,
            item.title,
            item.recovery.get("recoverability", "-"),
            item.confidence.value,
            item.evidence_count.get("fact", 0),
            "; ".join(item.uncertainties) or "-",
        ]
        for item in report.findings
    ]


def counterfactual_rows(report: AnalysisReport) -> list[list[Any]]:
    return [
        [
            f"{item.op.kind} {item.op.target_id}",
            f"{item.severity_before.value} -> {item.severity_after.value}",
            len(item.capabilities_removed),
            item.narrative,
        ]
        for item in report.counterfactuals
    ]


def honesty_markdown(report: AnalysisReport) -> str:
    """The section that keeps the product honest: what was refused and what stayed unknown."""
    lines = ["### Rejected agentic claims (shown, not hidden)", ""]
    lines += [
        f"- `{item.reason}` — {item.claim}" for item in report.agent_rejected_claims[:12]
    ] or ["_none_"]
    lines += ["", "### Untrusted-content signals", ""]
    lines += [
        f"- `{item.source_ref}`: {item.pattern} ({item.handling})"
        for item in report.injection_attempts[:12]
    ] or ["_none_"]
    lines += ["", "### Contradictions", ""]
    lines += [
        f"- **{item.code}** {item.subject}: {item.message}" for item in report.contradictions[:12]
    ] or ["_none_"]
    return "\n".join(lines)


def trajectory_rows(report: AnalysisReport) -> list[dict[str, Any]]:
    return [
        {"step": step.step, "phase": step.phase, "summary": step.summary}
        for step in report.trajectory
    ]


def chain_view(report: AnalysisReport, scenario: Scenario | None) -> dict[str, Any]:
    """Agent -> tool -> credential -> identity -> target, per capability."""
    return {
        "expected": scenario_expectation_summary(scenario) if scenario is not None else {},
        "capability_chains": [
            {"capability": f"{item.action.value}->{item.target}", "chain": " -> ".join(item.path)}
            for item in report.capabilities
        ],
        "distinct_targets": sorted({item.target for item in report.capabilities}),
        "agentic_only": [
            f"{item.action.value}->{item.target}"
            for item in report.capabilities
            if item.discovered_by != "deterministic"
        ],
    }


def expectations_markdown(scenario: Scenario | None) -> str:
    if scenario is None:
        return "*Select a scenario to see what the ground truth expects.*"
    return (
        "**Ground truth for this scenario**\n\n```json\n"
        + json.dumps(scenario_expectation_summary(scenario), indent=2)
        + "\n```"
    )
