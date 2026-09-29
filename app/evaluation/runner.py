"""Evaluation runner: execute scenarios in a run mode and collect artifacts.

The runner is the mechanical half of the ablation study (docs/EVALUATION_PLAN.md §4). It does not
judge; it runs, scores, and writes ``metrics.json`` plus a Markdown summary so results are
reproducible from the repository alone.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import DATA_DIR, Settings, get_settings
from app.evaluation.metrics import (
    EvaluationSummary,
    ScenarioResult,
    score_scenario,
    summarise,
)
from app.evaluation.quality import (
    QUALITY_SCALAR_FAMILIES,
    QualityScores,
    derive_scores,
    merge_scores,
    score_quality,
    verify_counterfactuals,
)
from app.schemas.analysis import AnalysisReport, CounterfactualOp
from app.schemas.common import RunMode
from app.schemas.scenario import Scenario
from app.services.loader import (
    DataRegistry,
    build_analysis_input,
    load_registry,
    load_scenarios,
)
from app.services.orchestrator import analyse


def rerun_for_counterfactual(
    scenario: Scenario,
    registry: DataRegistry,
    run_mode: RunMode,
    settings: Settings,
) -> Callable[[CounterfactualOp], AnalysisReport]:
    """Build the re-run callable that :func:`verify_counterfactuals` needs.

    Counterfactual accuracy is only a real measurement if the prediction is checked by *running the
    analysis again* with the edit applied. Returning a closure keeps the verifier agnostic about how
    the second run is produced, and pins the run mode and settings of the first run so the only
    difference between the two reports is the edit itself.
    """

    def _rerun(op: CounterfactualOp) -> AnalysisReport:
        from app.analyzers.counterfactual import apply_op

        edited = apply_op(build_analysis_input(registry, scenario, run_mode=run_mode), op)
        return analyse(edited, run_mode=run_mode, settings=settings).report

    return _rerun


def scenario_path(scenario_id: str, data_dir: Path | None = None) -> Path:
    root = Path(data_dir) if data_dir is not None else DATA_DIR / "scenarios"
    for path in sorted(root.glob("*.y*ml")):
        if path.stem.startswith(scenario_id) or path.stem == scenario_id:
            return path
    raise FileNotFoundError(f"no scenario file for {scenario_id!r} under {root}")


def run_scenario(
    scenario: Scenario,
    registry: DataRegistry,
    *,
    run_mode: RunMode = RunMode.A_DETERMINISTIC,
    keep_report: bool = False,
    prefer_real_llm: bool = False,
    with_quality: bool = True,
    verify_counterfactual_predictions: bool = True,
) -> tuple[ScenarioResult, AnalysisReport | None]:
    """Run one scenario and score it. Returns ``(result, report_or_None)``.

    The harness pins the scripted client unless ``prefer_real_llm`` is set, so an evaluation sweep is
    reproducible, free, and offline. Pass ``True`` (or set ``LLM_PREFER_REAL=true``) for a
    model-backed run; the client name is recorded in every artifact so the two are never confused.

    The §5 metric families in :mod:`app.evaluation.quality` are attached to the result here rather
    than left as an unused module: a metric nobody runs cannot support any claim, so the harness
    computes them as part of the ordinary sweep. Counterfactual predictions are additionally
    re-verified by re-running the analysis with each edit applied, which is the only way that
    accuracy is a measurement rather than a self-assessment.
    """
    from app.graph.builder import build_graph

    settings = get_settings()
    if prefer_real_llm is not None:
        settings = settings.model_copy(update={"llm_prefer_real": prefer_real_llm})
    try:
        analysis_input = build_analysis_input(registry, scenario, run_mode=run_mode)
        outcome = analyse(
            analysis_input, run_mode=run_mode, settings=settings, with_counterfactuals=True
        )
    except Exception as error:
        result = ScenarioResult(
            scenario_id=scenario.id,
            run_mode=run_mode,
            difficulty=scenario.difficulty,
            error=f"{type(error).__name__}: {error}",
        )
        return result, None

    report: AnalysisReport = outcome.report
    result = score_scenario(scenario, report)
    if with_quality:
        # The graph is rebuilt here rather than taken from the engine so scoring stays a pure function
        # of the artifacts, exactly as docs/EVALUATION_PLAN.md §5 requires.
        result.quality = derive_scores(
            score_quality(scenario, report, build_graph(analysis_input))
        ).as_dict()
        if verify_counterfactual_predictions and report.counterfactuals:
            verified = verify_counterfactuals(
                report, rerun_for_counterfactual(scenario, registry, run_mode, settings)
            )
            # Only the counterfactual columns are taken from the verification pass; everything else was
            # already measured above, and overwriting it here would discard the real counts.
            verified_scores = derive_scores(verified)
            result.quality.update(
                {
                    "counterfactual_accuracy": verified_scores.counterfactual_accuracy,
                    "counterfactual_severity_accuracy": verified_scores.counterfactual_severity_accuracy,
                    "counterfactual_no_unpredicted": verified_scores.counterfactual_no_unpredicted,
                    "counterfactual_failures": verified.counterfactual_failures,
                    "counterfactuals_evaluated": verified.counterfactuals_evaluated,
                }
            )
    if not keep_report:
        return result, None
    return result, report


def evaluate(
    run_mode: RunMode = RunMode.A_DETERMINISTIC,
    *,
    registry: DataRegistry | None = None,
    scenarios: list[Scenario] | None = None,
    prefer_real_llm: bool = False,
) -> tuple[EvaluationSummary, dict[str, AnalysisReport]]:
    """Run the whole scenario set in one mode and return ``(summary, per_scenario_reports)``."""
    registry = registry or load_registry()
    scenarios = scenarios or load_scenarios(DATA_DIR / "scenarios")
    results: list[ScenarioResult] = []
    reports: dict[str, AnalysisReport] = {}
    for scenario in scenarios:
        result, report = run_scenario(
            scenario, registry, run_mode=run_mode, keep_report=True, prefer_real_llm=prefer_real_llm
        )
        results.append(result)
        if report is not None:
            reports[scenario.id] = report
    summary = summarise(results, run_mode)
    # The §5 families, aggregated across scenarios. merge_scores skips families a scenario never
    # exercised rather than averaging in a zero, and reports how many scenarios contributed to each
    # rate so a thin number is visible as thin.
    summary.quality = merge_quality(results)
    return summary, reports


def merge_quality(results: list[ScenarioResult]) -> dict[str, object]:
    """Aggregate the per-scenario §5 dicts into one table.

    Only scenarios that actually produced quality scores contribute. Scenarios that errored out are
    skipped rather than counted as failing every family, because a crashed run is not evidence of
    poor analysis quality -- and the count of contributing scenarios is reported so the reader can
    tell the two apart.
    """
    scores: list[QualityScores] = []
    for result in results:
        if not result.quality:
            continue
        known = {
            key: result.quality[key] for key in QUALITY_SCALAR_FAMILIES if key in result.quality
        }
        if not known:
            continue
        scores.append(QualityScores(**known))
    merged = merge_scores(scores)
    merged["scenarios_contributing"] = len(scores)
    merged["scenarios_total"] = len(results)
    return merged


def write_artifacts(summary: EvaluationSummary, output_dir: Path | None = None) -> Path:
    """Write ``metrics.json`` and ``report.md`` for one run mode."""
    settings = get_settings()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = (output_dir or settings.eval_output_path()) / f"{summary.run_mode.value}-{stamp}"
    target.mkdir(parents=True, exist_ok=True)
    (target / "metrics.json").write_text(
        json.dumps(summary.as_dict(), indent=2, default=str), encoding="utf-8"
    )
    (target / "report.md").write_text(render_markdown(summary), encoding="utf-8")
    return target


def render_markdown(summary: EvaluationSummary) -> str:
    """Human-readable summary of one run mode."""
    lines: list[str] = []
    lines.append(f"# Evaluation report — {summary.run_mode.value}")
    lines.append("")
    lines.append(f"- scenarios: {len(summary.results)}")
    lines.append(f"- capability recall: {summary.recall:.3f}")
    lines.append(f"- capability precision: {summary.precision:.3f}")
    lines.append(f"- false positives: {summary.false_positives}")
    lines.append(f"- severity violations: {summary.severity_violations}")
    lines.append(f"- errors: {summary.errors}")
    lines.append("")
    lines.append("| scenario | difficulty | recall | FP | severity violations | missing |")
    lines.append("|---|---|---|---|---|---|")
    for result in summary.results:
        lines.append(
            f"| {result.scenario_id} | {result.difficulty} | {result.recall:.2f} | "
            f"{result.false_positives} | {len(result.severity_violations)} | "
            f"{', '.join(match.label for match in result.missing) or '-'} |"
        )
    lines.append("")

    # The §5 families. A "none" in the value column means the scenario set declares no ground truth
    # for that family, which is a very different statement from a score of zero and must not be
    # rendered as one.
    quality = summary.quality or {}
    if quality:
        lines.append("## Metric families (docs/EVALUATION_PLAN.md §5)")
        lines.append("")
        lines.append(
            f"Aggregated over {quality.get('scenarios_contributing', 0)} of "
            f"{quality.get('scenarios_total', len(summary.results))} scenarios that produced scores."
        )
        lines.append("")
        lines.append("| family | value | scenarios |")
        lines.append("|---|---|---|")
        for key in (
            "resource_precision",
            "resource_recall",
            "capability_precision",
            "capability_recall",
            "path_precision",
            "path_recall",
            "composition_recall",
            "stateful_recall",
            "mean_state_depth_error",
            "evidence_accuracy",
            "hallucination_rate",
            "explanation_faithfulness",
            "counterfactual_accuracy",
            "counterfactual_severity_accuracy",
            "counterfactual_no_unpredicted",
            "contradiction_precision",
            "contradiction_recall",
            "uncertainty_coverage",
        ):
            entry = quality.get(key)
            if not isinstance(entry, dict):
                continue
            value = entry.get("value")
            rendered = "none (no ground truth)" if value is None else f"{value}"
            lines.append(f"| {key} | {rendered} | {entry.get('scenarios', 0)} |")
        for band, value in sorted((quality.get("false_positive_rate_by_band") or {}).items()):
            lines.append(f"| fp_rate_{band} | {value} | - |")
        for band, value in sorted((quality.get("false_negative_rate_by_band") or {}).items()):
            rendered = "none (no ground truth)" if value is None else f"{value}"
            lines.append(f"| fn_rate_{band} | {rendered} | - |")
        efficiency = quality.get("reasoning_efficiency") or {}
        for key in sorted(efficiency):
            lines.append(f"| {key} (mean) | {efficiency[key]} | - |")
        notes = quality.get("notes") or []
        if notes:
            lines.append("")
            lines.append("Notes:")
            for note in notes:
                lines.append(f"- {note}")
    return "\n".join(lines) + "\n"


def ablation(
    modes: tuple[RunMode, ...] = (
        RunMode.A_DETERMINISTIC,
        RunMode.B_INTERPRET,
        RunMode.C_AGENTIC,
        RunMode.D_FULL,
    ),
    *,
    registry: DataRegistry | None = None,
) -> dict[str, dict[str, Any]]:
    """Run several modes over the same scenarios and return the comparison table.

    The value type is ``dict[str, Any]`` because every entry is one run mode's serialised summary.
    Declaring ``object`` here forced every consumer -- the Markdown generator in particular -- to cast
    or suppress, which is how a genuine shape mismatch would have gone unnoticed.
    """
    registry = registry or load_registry()
    table: dict[str, dict[str, Any]] = {}
    for mode in modes:
        summary, _reports = evaluate(mode, registry=registry)
        payload = summary.as_dict()
        payload.pop("scenarios_detail", None)
        table[mode.value] = payload
    return table
