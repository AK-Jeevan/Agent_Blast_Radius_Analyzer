"""Scoring one report against one scenario's ground truth.

Metrics are computed over capability *triples* ``(action, target, environment)``. A capability at
``CONTRADICTED`` or ``UNVERIFIED`` status is excluded from the reported set and scored separately:
counting a self-declared guess as a hit would reward over-claiming.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.schemas.analysis import AnalysisReport
from app.schemas.common import (
    ActionClass,
    RunMode,
    Severity,
    VerificationStatus,
    severity_rank,
    status_rank,
)
from app.schemas.scenario import ExpectedCapability, Scenario

#: Statuses that count towards recall (the report is claiming these are real).
COUNTED_STATUSES = frozenset(
    {
        VerificationStatus.CONFIRMED,
        VerificationStatus.PROBABLE,
        VerificationStatus.POSSIBLE,
    }
)


def expected_label(expectation: ExpectedCapability) -> str:
    suffix = f"@{expectation.environment}" if expectation.environment else ""
    return f"{expectation.action.value}->{expectation.target}{suffix}"


@dataclass
class CapabilityMatch:
    """One ground-truth expectation and how the report answered it."""

    label: str
    expected_min: Severity | None
    expected_max: Severity | None
    found: bool
    actual_severity: Severity | None
    actual_status: VerificationStatus | None
    severity_ok: bool
    state_depth_ok: bool
    via_ok: bool
    via_missing: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class ScenarioResult:
    """Everything scored for one scenario in one run mode."""

    scenario_id: str
    run_mode: RunMode
    difficulty: str
    found: list[CapabilityMatch] = field(default_factory=list)
    missing: list[CapabilityMatch] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    false_positive_details: list[str] = field(default_factory=list)
    unlisted_findings: list[str] = field(default_factory=list)
    severity_violations: list[str] = field(default_factory=list)
    expected_uncertainties_hit: list[str] = field(default_factory=list)
    expected_uncertainties_missed: list[str] = field(default_factory=list)
    contradictions_found: list[str] = field(default_factory=list)
    contradictions_expected: list[str] = field(default_factory=list)
    predicted_baseline_misses: list[str] = field(default_factory=list)
    actual_baseline_misses: list[str] = field(default_factory=list)
    reported_capabilities: int = 0
    max_severity: Severity = Severity.INFO
    latency_ms: int = 0
    llm_calls: int = 0
    tool_calls: int = 0
    caps_hit: list[str] = field(default_factory=list)
    #: The §5 metric families (app.evaluation.quality) for this scenario. A dict rather than a typed
    #: field because the families are intentionally allowed to report ``None`` for "no ground truth",
    #: and a typed float would force that to be flattened into a misleading 0.0.
    quality: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def required_total(self) -> int:
        return len(self.found) + len(self.missing)

    @property
    def true_positives(self) -> int:
        return sum(1 for match in self.found if match.found)

    @property
    def false_positives(self) -> int:
        """Only a *forbidden* capability counts as a false positive.

        Scenarios deliberately do not enumerate every real capability, so a finding that is neither
        expected nor forbidden is reported as informational rather than penalised.
        """
        return len(self.false_positive_details)

    @property
    def recall(self) -> float:
        if self.error:
            # A scenario that failed to run is not a perfect score: it is a missing result.
            return 0.0
        return self.true_positives / self.required_total if self.required_total else 1.0

    @property
    def precision(self) -> float:
        if self.error:
            return 0.0
        if not self.reported_capabilities:
            return 1.0
        return 1.0 - self.false_positives / self.reported_capabilities

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "run_mode": self.run_mode.value,
            "difficulty": self.difficulty,
            "reported_capabilities": self.reported_capabilities,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "required": self.required_total,
            "recall": round(self.recall, 3),
            "precision": round(self.precision, 3),
            "missing": [match.label for match in self.missing],
            "false_positive_details": self.false_positive_details,
            "unlisted_findings": self.unlisted_findings,
            "severity_violations": self.severity_violations,
            "max_severity": self.max_severity.value,
            "contradictions_found": self.contradictions_found,
            "contradictions_expected": self.contradictions_expected,
            "uncertainties_missed": self.expected_uncertainties_missed,
            "predicted_baseline_misses": self.predicted_baseline_misses,
            "actual_baseline_misses": self.actual_baseline_misses,
            "latency_ms": self.latency_ms,
            "llm_calls": self.llm_calls,
            "tool_calls": self.tool_calls,
            "caps_hit": self.caps_hit,
            "quality": self.quality,
            "error": self.error,
        }


def _match_expectation(expectation: ExpectedCapability, report: AnalysisReport) -> CapabilityMatch:
    candidates = [
        capability
        for capability in report.capabilities
        if capability.action == expectation.action and capability.target == expectation.target
    ]
    if expectation.environment is not None:
        candidates = [
            capability
            for capability in candidates
            if capability.environment == expectation.environment
        ]
    if not candidates:
        return CapabilityMatch(
            label=expected_label(expectation),
            expected_min=expectation.min_severity,
            expected_max=expectation.max_severity,
            found=False,
            actual_severity=None,
            actual_status=None,
            severity_ok=True,
            state_depth_ok=True,
            via_ok=True,
            reason="no capability reported for this triple",
        )

    best = max(
        candidates,
        key=lambda capability: (
            severity_rank(capability.severity),
            status_rank(capability.verification_status),
        ),
    )
    severity_ok = best.verification_status in COUNTED_STATUSES
    if expectation.min_severity is not None:
        severity_ok = severity_ok and severity_rank(best.severity) >= severity_rank(
            expectation.min_severity
        )
    if expectation.max_severity is not None:
        severity_ok = severity_ok and severity_rank(best.severity) <= severity_rank(
            expectation.max_severity
        )

    # A *derived* capability (DESTROY, EXFILTRATE) records the entities it was derived *from* in
    # ``derived_from`` rather than splicing them into ``path``: a path is a chain of graph edges, and
    # appending a backup the chain already terminates on would render as a self-loop, while the only
    # real edges run backwards from the target. The derivation is still fully auditable, so
    # ``derived_from`` counts as cited provenance. Without this, a scenario that correctly expects the
    # backup to be involved in an irreversibility finding was reported as missing it.
    cited = set(best.path) | set(best.provenance) | set(getattr(best, "derived_from", None) or [])
    via_missing = [item for item in expectation.via if item not in cited]
    # `via` lists alternative hops ("the chain runs through the deploy tool *or* the HTTP tool"), so
    # the check is "at least one expected entity is present" rather than "all of them".
    via_ok = not expectation.via or any(item in cited for item in expectation.via)
    return CapabilityMatch(
        label=expected_label(expectation),
        expected_min=expectation.min_severity,
        expected_max=expectation.max_severity,
        found=True,
        actual_severity=best.severity,
        actual_status=best.verification_status,
        severity_ok=severity_ok,
        state_depth_ok=best.state_depth >= expectation.min_state_depth,
        via_ok=via_ok,
        via_missing=via_missing,
        reason="reported as expected"
        if severity_ok
        else "unexpected severity or verification status",
    )


def score_scenario(scenario: Scenario, report: AnalysisReport) -> ScenarioResult:
    """Score one report against one scenario's expectations."""
    result = ScenarioResult(
        scenario_id=scenario.id,
        run_mode=report.run_mode,
        difficulty=scenario.difficulty,
        max_severity=report.risk_summary.overall_severity,
        latency_ms=report.metrics.latency_ms,
        llm_calls=report.metrics.llm_calls,
        tool_calls=report.metrics.tool_calls,
        caps_hit=list(report.metrics.caps_hit),
    )
    counted = {
        (capability.action, capability.target, capability.environment)
        for capability in report.capabilities
        if capability.verification_status in COUNTED_STATUSES
    }
    result.reported_capabilities = len(counted)

    expected_triples: set[tuple[ActionClass, str, str | None]] = set()
    for expectation in scenario.expectations.must_find_capabilities:
        match = _match_expectation(expectation, report)
        expected_triples.add((expectation.action, expectation.target, expectation.environment))
        (result.found if match.found else result.missing).append(match)

    forbidden = {
        (expectation.action, expectation.target, expectation.environment)
        for expectation in scenario.expectations.must_not_find_capabilities
    }
    for expectation in scenario.expectations.must_not_find_capabilities:
        hit = any(
            capability.action == expectation.action
            and capability.target == expectation.target
            and (
                expectation.environment is None or capability.environment == expectation.environment
            )
            and capability.verification_status in COUNTED_STATUSES
            for capability in report.capabilities
        )
        if hit:
            result.false_positive_details.append(expected_label(expectation))
            result.unexpected.append(expected_label(expectation))
    for action, target, _environment in sorted(counted - expected_triples - forbidden, key=str):
        result.unlisted_findings.append(f"{action.value}->{target}")

    if scenario.expectations.max_severity is not None and severity_rank(
        report.risk_summary.overall_severity
    ) > severity_rank(scenario.expectations.max_severity):
        result.severity_violations.append(
            f"overall severity {report.risk_summary.overall_severity.value} exceeds the scenario "
            f"ceiling {scenario.expectations.max_severity.value}"
        )
    for match in result.found:
        if not match.severity_ok:
            result.severity_violations.append(f"{match.label}: {match.reason}")
        if not match.state_depth_ok:
            result.severity_violations.append(f"{match.label}: state depth below the minimum")
        if not match.via_ok:
            result.severity_violations.append(
                f"{match.label}: expected provenance not on the path "
                f"(missing {', '.join(match.via_missing)})"
            )

    reported_codes = {uncertainty.code for uncertainty in report.uncertainties}
    reported_codes |= {
        code for capability in report.capabilities for code in capability.uncertainties
    }
    for code in scenario.expectations.expected_uncertainties:
        if code in reported_codes:
            result.expected_uncertainties_hit.append(code)
        else:
            result.expected_uncertainties_missed.append(code)

    result.predicted_baseline_misses = list(scenario.expectations.expected_baseline_misses)
    result.actual_baseline_misses = [match.label for match in result.missing]
    result.contradictions_expected = list(scenario.expectations.expected_contradictions)
    result.contradictions_found = [item.code for item in report.contradictions]
    return result


@dataclass
class EvaluationSummary:
    """Aggregate metrics for one run mode over a set of scenarios."""

    run_mode: RunMode
    results: list[ScenarioResult] = field(default_factory=list)
    #: The §5 metric families aggregated across scenarios, filled in by the harness runner. Kept as
    #: loose data because those families carry ``None`` for "no ground truth", which a typed float
    #: field would force into a misleading 0.0.
    quality: dict[str, Any] = field(default_factory=dict)

    @property
    def total_required(self) -> int:
        return sum(result.required_total for result in self.results)

    @property
    def true_positives(self) -> int:
        return sum(result.true_positives for result in self.results)

    @property
    def false_positives(self) -> int:
        return sum(result.false_positives for result in self.results)

    @property
    def recall(self) -> float:
        return self.true_positives / self.total_required if self.total_required else 1.0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    @property
    def false_positive_rate(self) -> float:
        reported = self.true_positives + self.false_positives
        return self.false_positives / reported if reported else 0.0

    @property
    def severity_violations(self) -> int:
        return sum(len(result.severity_violations) for result in self.results)

    @property
    def errors(self) -> int:
        return sum(1 for result in self.results if result.error)

    def by_difficulty(self) -> dict[str, dict[str, float]]:
        buckets: dict[str, list[ScenarioResult]] = {}
        for result in self.results:
            buckets.setdefault(result.difficulty, []).append(result)
        return {
            difficulty: {
                "scenarios": float(len(items)),
                "recall": round(sum(item.recall for item in items) / len(items), 3),
                "false_positives": float(sum(item.false_positives for item in items)),
            }
            for difficulty, items in sorted(buckets.items())
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_mode": self.run_mode.value,
            "scenarios": len(self.results),
            "capability_recall": round(self.recall, 3),
            "capability_precision": round(self.precision, 3),
            "f1": round(self.f1, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "severity_violations": self.severity_violations,
            "errors": self.errors,
            "by_difficulty": self.by_difficulty(),
            "quality": self.quality,
            "scenarios_detail": [result.as_dict() for result in self.results],
        }


def summarise(results: list[ScenarioResult], run_mode: RunMode) -> EvaluationSummary:
    """Aggregate per-scenario results into one summary object."""
    return EvaluationSummary(run_mode=run_mode, results=results)
