"""Deterministic analysis engine: build the graph, run the closure, assemble the report.

``run_deterministic`` is Version A of the ablation study (docs/EVALUATION_PLAN.md §4). It must stay
fast, dependency-free, and byte-reproducible: the agentic layer is scored *against* this function,
so a change here is a change to the control.
"""

from __future__ import annotations

import time
from typing import Any

from app.analyzers.authz import PolicyEvaluator
from app.analyzers.blast_radius import assemble_report
from app.analyzers.closure import run_closure
from app.analyzers.credentials import analyse_credentials
from app.analyzers.evidence import EvidenceLedger
from app.analyzers.reachability import ReachabilityAnalyzer
from app.analyzers.report import finalise_report
from app.config import Settings, get_settings
from app.graph.builder import EnvironmentGraph, build_graph
from app.schemas.analysis import AnalysisInput, AnalysisReport
from app.schemas.common import RunMode
from app.utils.ids import content_hash

PIPELINE = "graph>authz>reachability>credentials>closure>evidence>scoring>report"


def run_deterministic(
    analysis_input: AnalysisInput,
    *,
    analysis_id: str | None = None,
    settings: Settings | None = None,
) -> AnalysisReport:
    """Run the deterministic analyzer end to end for one agent environment."""
    settings = settings or get_settings()
    started = time.perf_counter()
    analysis_id = analysis_id or make_analysis_id(analysis_input)

    ledger = EvidenceLedger()
    environment = build_graph(analysis_input)
    reachability = ReachabilityAnalyzer(environment)
    evaluator = PolicyEvaluator(analysis_input)
    credential_statuses = analyse_credentials(analysis_input)

    closure = run_closure(
        analysis_input,
        environment,
        ledger,
        reachability,
        evaluator,
        credential_statuses,
        max_state_depth=settings.max_state_depth,
    )

    report = assemble_report(
        analysis_input,
        environment,
        reachability,
        ledger,
        closure,
        analysis_id=analysis_id,
        run_mode=RunMode.A_DETERMINISTIC,
        min_facts_for_high=settings.min_facts_for_high_severity,
    )
    report.metrics.latency_ms = int((time.perf_counter() - started) * 1000)
    report.metrics.caps_hit = list(closure.caps_hit)
    finalise_report(report)
    return report


def make_analysis_id(analysis_input: AnalysisInput) -> str:
    """Deterministic analysis id derived from the analysed input (stable across repeats)."""
    fingerprint = content_hash(
        analysis_input.agent.id,
        sorted(item.id for item in analysis_input.tools),
        sorted(item.id for item in analysis_input.credentials),
        sorted(item.id for item in analysis_input.permissions),
        sorted(item.id for item in analysis_input.network),
        length=10,
    )
    return f"an-{fingerprint}"


def graph_snapshot(environment: EnvironmentGraph) -> dict[str, Any]:
    """Graph view for the API/UI (kept here so the API does not re-import the graph package)."""
    return environment.to_serialisable()
