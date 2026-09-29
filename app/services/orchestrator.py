"""Run modes and the orchestrator: one entry point, four configurations (docs/MVP_ARCHITECTURE.md §3).

The orchestrator always returns the deterministic result alongside the requested mode's result, so
the report can state plainly what the LLM layer added (or failed to add). That transparency is a
product requirement, not a debug convenience.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.analyzers.engine import PIPELINE, make_analysis_id, run_deterministic
from app.config import Settings, get_settings
from app.schemas.analysis import AnalysisInput, AnalysisReport, Capability
from app.schemas.common import RunMode
from app.utils.ids import content_hash


@dataclass
class AnalysisOutcome:
    """One analysed environment: the requested mode's report plus the baseline it was judged against."""

    report: AnalysisReport
    baseline: AnalysisReport
    notes: list[str] = field(default_factory=list)

    @property
    def run_mode(self) -> RunMode:
        return self.report.run_mode


def _agentic_outcome(
    analysis_input: AnalysisInput,
    baseline: AnalysisReport,
    mode: RunMode,
    settings: Settings,
) -> tuple[AnalysisReport, list[Capability]]:
    """Run the agentic layer for a mode, tolerating its absence.

    The agentic layer is optional by design: with no client configured (no API key) the system
    degrades to the deterministic result and *says so*, rather than pretending an LLM contributed.
    The caller's settings are honoured, so a pinned (scripted) run really is pinned.
    """
    from app.agents.pipeline import AgenticAnalyzer, merge_agentic

    analyzer = AgenticAnalyzer(analysis_input, baseline, mode=mode, settings=settings)
    result = analyzer.run()
    return merge_agentic(baseline, result), result.capabilities


def analyse(
    analysis_input: AnalysisInput,
    *,
    run_mode: RunMode | None = None,
    settings: Settings | None = None,
    with_counterfactuals: bool = False,
) -> AnalysisOutcome:
    """Run the requested mode and return both the requested report and the deterministic baseline."""
    from app.analyzers.report import finalise_report

    settings = settings or get_settings()
    mode = run_mode or analysis_input.run_mode or RunMode(settings.default_run_mode)
    started = time.perf_counter()

    baseline = run_deterministic(analysis_input, settings=settings)
    notes: list[str] = []
    report = baseline
    if mode != RunMode.A_DETERMINISTIC:
        report, added = _agentic_outcome(analysis_input, baseline, mode, settings)
        if added:
            notes.append(
                f"{mode.value} verified {len(added)} extra capability(ies): "
                + ", ".join(f"{item.action.value}->{item.target}" for item in added)
            )
        else:
            notes.append(
                f"{mode.value} produced no additional capabilities: nothing survived verification"
            )
        report = report.model_copy(
            update={"run_mode": mode, "termination_reason": "verification_complete"}
        )

    if with_counterfactuals:
        from app.analyzers.counterfactual import counterfactual_suggestions

        report = report.model_copy(
            update={"counterfactuals": counterfactual_suggestions(analysis_input, report, settings)}
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    from app.analyzers.blast_radius import rebuild_findings, with_recomputed_summary

    report = rebuild_findings(report, min_facts_for_high=settings.min_facts_for_high_severity)
    report = with_recomputed_summary(report)
    report = report.model_copy(
        update={
            "metrics": report.metrics.model_copy(update={"latency_ms": latency_ms}),
            "baseline_comparison": report.baseline_comparison.model_copy(
                update={
                    "mode_a_capabilities": len(baseline.capabilities),
                    "requested_mode_capabilities": len(report.capabilities),
                    "added_by_agentic": sorted(
                        {
                            capability.id
                            for capability in report.capabilities
                            if capability.discovered_by != "deterministic"
                        }
                    ),
                    "rejected_agentic": [
                        rejection.claim for rejection in report.agent_rejected_claims
                    ][:20],
                    "notes": [*notes, f"deterministic pipeline: {PIPELINE}"],
                }
            ),
        }
    )
    # Render last, so the text and the machine-checkable narrative reflect the final numbers.
    return AnalysisOutcome(report=finalise_report(report), baseline=baseline, notes=notes)


def fingerprint(analysis_input: AnalysisInput) -> str:
    """Stable fingerprint of an analysed environment (used for run ids and caching)."""
    return content_hash(
        analysis_input.model_dump_json(exclude_none=False, exclude={"run_mode"}), length=16
    )


__all__ = ["AnalysisOutcome", "analyse", "fingerprint", "make_analysis_id"]
