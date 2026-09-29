"""Evaluation harness: run scenarios, score them against ground truth, and report metrics.

Metric definitions live in ``docs/EVALUATION_PLAN.md`` §5; this module implements them. The
harness is deliberately separate from the engine so that scoring can be re-run against stored
reports without re-running analysis.
"""

from __future__ import annotations

from app.evaluation.metrics import (
    EvaluationSummary,
    ScenarioResult,
    score_scenario,
    summarise,
)
from app.evaluation.runner import evaluate, run_scenario

__all__ = [
    "EvaluationSummary",
    "ScenarioResult",
    "evaluate",
    "run_scenario",
    "score_scenario",
    "summarise",
]
