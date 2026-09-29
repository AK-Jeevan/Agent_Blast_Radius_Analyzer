"""Tests for the §5 metric families in :mod:`app.evaluation.quality`.

The point of these tests is not that the arithmetic works — it is that the metrics *cannot quietly
lie*. The recurring theme: a family with no ground truth must report ``None`` rather than a
flattering 1.0, evidence support must be checked against what the evidence actually says, and the
determinism fingerprint must ignore the fields that differ between any two runs by construction.

Several tests here were added after the metrics were first wired into the harness and immediately
found disagreeing with the engine. Each of those disagreements turned out to be a defect in the
*metric* rather than in the analyzer — an undefined family reported as 0.0, a numerator and
denominator drawn from different populations, a support test so strict it rejected legitimate
citations — and each is now pinned by an executable check so the metric cannot drift back into
lying about the engine it is supposed to measure.
"""

from __future__ import annotations

from typing import cast

import pytest

from app.config import DATA_DIR, get_settings
from app.evaluation.quality import (
    HIGH_PLUS,
    SEVERITY_BANDS,
    QualityMetrics,
    _as_nx,
    _has_edge,
    _path_edges,
    band_of,
    derive_scores,
    determinism_fingerprint,
    merge_scores,
    score_quality,
    verify_counterfactuals,
)
from app.graph.builder import EnvironmentGraph, build_graph
from app.schemas.analysis import AnalysisReport, CounterfactualOp, CounterfactualResult
from app.schemas.common import RunMode, Severity
from app.schemas.scenario import Scenario
from app.services.loader import (
    DataRegistry,
    build_analysis_input,
    load_registry,
    load_scenarios,
)
from app.services.orchestrator import analyse

pytestmark = pytest.mark.unit

#: Scalar floats in :meth:`QualityScores.as_dict` that are not rates, and so are not bounded to
#: [0, 1]. A mean absolute error is floored at zero and has no ceiling, so asserting the rate bounds
#: over it would eventually fail for a perfectly good metric the first time a scenario is off by two
#: state depths.
NON_RATE_FIELDS = frozenset({"mean_state_depth_error"})


@pytest.fixture(scope="module")
def registry() -> DataRegistry:
    """The validated data corpus, loaded once: it is the most expensive fixture in the suite."""
    return load_registry()


@pytest.fixture(scope="module")
def scenarios() -> list[Scenario]:
    """Every scenario in the corpus, in file order."""
    return load_scenarios(DATA_DIR / "scenarios")


def _analyse(
    scenario: Scenario,
    registry: DataRegistry,
    mode: RunMode = RunMode.D_FULL,
) -> tuple[AnalysisReport, EnvironmentGraph]:
    # The scripted client is pinned so the test never depends on a network round trip, and so the
    # numbers in the assertions are the reproducible ones. Counterfactuals are generated here because
    # several of the metric families below only have something to measure when the report carries them.
    settings = get_settings().model_copy(update={"llm_prefer_real": False})
    analysis_input = build_analysis_input(registry, scenario, run_mode=mode)
    report = analyse(
        analysis_input, run_mode=mode, settings=settings, with_counterfactuals=True
    ).report
    return report, build_graph(analysis_input)


def _by_id(scenarios: list[Scenario], prefix: str) -> Scenario:
    """The one scenario whose id starts with ``prefix``.

    Raises ``StopIteration`` when nothing matches, which surfaces as a test failure naming the
    prefix. That is the intended behaviour: a renamed or deleted scenario must fail loudly rather
    than silently let a test pass against a different one.
    """
    return next(item for item in scenarios if item.id.startswith(prefix))


def _stub_report(
    capabilities: list[object],
    overall_severity: Severity,
) -> AnalysisReport:
    """A minimal stand-in for an AnalysisReport, for counterfactual verification.

    ``verify_counterfactuals`` only reads ``capabilities`` (their ``.id``) and
    ``risk_summary.overall_severity``, so a real report is not needed to exercise it -- and building
    one would drag the whole engine into a unit test. The cast is explicit rather than a bare
    ``type(...)`` stub: a locally-constructed class is ``Any`` to a type checker, so the assertion
    that it stands in for a report has to be stated rather than implied.
    """
    stub = type(
        "StubReport",
        (),
        {
            "capabilities": capabilities,
            "risk_summary": type("StubRisk", (), {"overall_severity": overall_severity})(),
        },
    )()
    return cast(AnalysisReport, stub)


def _stub_counterfactual_report(
    capabilities: list[object],
    counterfactuals: list[CounterfactualResult],
) -> AnalysisReport:
    """A stand-in for a report that carries counterfactual predictions.

    ``verify_counterfactuals`` is the only consumer, and it reads ``capabilities``,
    ``counterfactuals`` and ``risk_summary.overall_severity``. The tests that need a trivial or
    deliberately-wrong report build one here so that the cast is stated in one place, for the same
    reason :func:`_stub_report` states its own: a locally constructed class is ``Any`` to a type
    checker, so the claim that it stands in for a report has to be asserted rather than implied.
    """
    stub = type(
        "StubCounterfactualReport",
        (),
        {"capabilities": capabilities, "counterfactuals": counterfactuals},
    )()
    return cast(AnalysisReport, stub)


# ------------------------------------------------------------------ bands ----
def test_every_severity_lands_in_exactly_one_band() -> None:
    assigned = [band_of(severity) for severity in Severity]
    assert len(assigned) == len(set(assigned)), "a severity is in two bands"
    assert set(assigned) == set(SEVERITY_BANDS)


def test_high_plus_is_critical_and_high() -> None:
    assert set(HIGH_PLUS) == {"critical", "high"}


# ------------------------------------------------------- honest undefined ----
def test_a_family_without_ground_truth_reports_none_not_zero() -> None:
    """No stateful expectations means no stateful score, not a perfect one."""
    scores = derive_scores(QualityMetrics())
    assert scores.stateful_recall is None
    assert scores.composition_recall is None
    assert scores.contradiction_recall is None
    assert scores.uncertainty_coverage is None
    assert scores.evidence_accuracy is None
    # A metric with no *claims* is not a metric with zero bad claims.
    assert scores.false_positive_rate_high_plus == 0.0
    assert scores.hallucination_rate is None


def test_notes_explain_why_a_family_is_empty() -> None:
    scores = derive_scores(QualityMetrics())
    assert any("ground-truth resources" in note for note in scores.notes)


# -------------------------------------------------------------- real runs ----
def test_path_precision_is_one_when_the_graph_is_supplied(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """Every hop the report claims must be a real edge — otherwise the claim is fabricated."""
    scenario = _by_id(scenarios, "scenario-08")
    report, graph = _analyse(scenario, registry)
    metrics = score_quality(scenario, report, graph)
    scores = derive_scores(metrics)
    assert metrics.path_hops > 0
    assert scores.path_precision == 1.0


def test_path_scores_are_undefined_without_a_graph(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    scenario = _by_id(scenarios, "scenario-08")
    report, _graph = _analyse(scenario, registry)
    scores = derive_scores(score_quality(scenario, report, None))
    assert scores.path_precision is None, "an unverifiable path must not score as perfect"


def test_evidence_citations_all_resolve(registry: DataRegistry, scenarios: list[Scenario]) -> None:
    scenario = _by_id(scenarios, "scenario-01")
    report, _graph = _analyse(scenario, registry)
    known = {item.id for item in report.evidence}
    for capability in report.capabilities:
        for citation in capability.evidence:
            assert citation in known, "the engine emitted a dangling citation"


def test_explanation_faithfulness_is_measured_on_the_narrative(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    scenario = _by_id(scenarios, "scenario-01")
    report, graph = _analyse(scenario, registry)
    metrics = score_quality(scenario, report, graph)
    scores = derive_scores(metrics)
    assert metrics.narrative_sentences > 0, "the report carries no explanatory sentences"
    assert scores.explanation_faithfulness == 1.0
    assert not metrics.unsupported_sentences


def test_every_narrative_citation_resolves_to_a_real_artifact(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """Every cited id must resolve to something the report actually contains.

    Citations are of two kinds and both are legitimate: evidence ids (``ev-*``), which back a claim
    about the environment, and capability ids (``cap-*``), which counterfactual statements cite to name
    the capabilities they claim to add or remove. An earlier version of this test asserted every
    citation was an evidence id, which pushed the counterfactual sentences toward citing something less
    meaningful purely to satisfy the check. The requirement is resolvability, not one namespace.
    """
    for scenario in scenarios:
        report, _graph = _analyse(scenario, registry)
        known = {item.id for item in report.evidence} | {item.id for item in report.capabilities}
        for statement in report.narrative:
            for citation in statement.evidence_ids:
                assert citation in known, (
                    f"{scenario.id}: {citation!r} is cited but names nothing in the report"
                )


def test_capability_scores_agree_with_the_headline_harness(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """The §5 rates and the headline metrics.py numbers must not drift apart."""
    from app.evaluation.metrics import score_scenario

    scenario = _by_id(scenarios, "scenario-01")
    report, graph = _analyse(scenario, registry)
    headline = score_scenario(scenario, report)
    scores = derive_scores(score_quality(scenario, report, graph))
    assert scores.capability_recall == pytest.approx(headline.recall, abs=1e-4)


def test_per_band_rates_are_present_for_every_band(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    scenario = _by_id(scenarios, "scenario-01")
    report, graph = _analyse(scenario, registry)
    scores = derive_scores(score_quality(scenario, report, graph))
    assert set(scores.false_positive_rate_by_band) == set(SEVERITY_BANDS)
    assert set(scores.false_negative_rate_by_band) == set(SEVERITY_BANDS)
    assert scores.false_positive_rate_high_plus == 0.0, "a clean run must report zero FP"


def test_reasoning_efficiency_reports_every_planned_column(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    scenario = _by_id(scenarios, "scenario-08")
    report, graph = _analyse(scenario, registry)
    scores = derive_scores(score_quality(scenario, report, graph))
    assert set(scores.reasoning_efficiency) == {
        "llm_calls",
        "tool_calls",
        "input_tokens",
        "output_tokens",
        "latency_ms",
        "estimated_cost_usd",
        "steps_to_termination",
        "caps_hit",
    }
    assert scores.reasoning_efficiency["latency_ms"] > 0


# ------------------------------------------------------------ determinism ----
def test_fingerprint_ignores_volatile_fields(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """Latency and the analysis id differ in every run; including them would make the rule useless."""
    report, _graph = _analyse(_by_id(scenarios, "scenario-08"), registry)
    mutated = report.model_copy(
        update={
            "analysis_id": "an-different",
            "metrics": report.metrics.model_copy(
                update={"latency_ms": 999_999, "estimated_cost_usd": 12.34}
            ),
        }
    )
    assert determinism_fingerprint(report) == determinism_fingerprint(mutated)


def test_fingerprint_notices_a_real_change(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    report, _graph = _analyse(_by_id(scenarios, "scenario-08"), registry)
    mutated = report.model_copy(
        update={
            "capabilities": [
                *report.capabilities,
                report.capabilities[0].model_copy(update={"target": "res-something-else"}),
            ]
        }
    )
    assert determinism_fingerprint(report) != determinism_fingerprint(mutated)


def test_repeated_runs_are_deterministic(registry: DataRegistry, scenarios: list[Scenario]) -> None:
    """The validity rule of §5, as an executable check: A must be identical across repeats."""
    scenario = _by_id(scenarios, "scenario-08")
    prints = {
        determinism_fingerprint(_analyse(scenario, registry, RunMode.A_DETERMINISTIC)[0])
        for _ in range(3)
    }
    assert len(prints) == 1, "the deterministic baseline is not reproducible"


# ---------------------------------------------------------- counterfactuals ----
def test_counterfactual_verification_catches_a_wrong_prediction(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """A prediction that is never re-run is an opinion; this proves the check bites."""
    capability = _analyse(_by_id(scenarios, "scenario-01"), registry)[0].capabilities[0]
    report = _stub_counterfactual_report(
        [capability],
        [
            CounterfactualResult(
                op=CounterfactualOp(kind="remove_tool", target_id="tool-x"),
                capabilities_removed=["cap-does-not-exist"],
                severity_before=Severity.HIGH,
                severity_after=Severity.LOW,
            )
        ],
    )

    def _rerun(_op: CounterfactualOp) -> AnalysisReport:
        # The capability survives the edit, so the removal prediction must be marked wrong.
        return _stub_report([capability], Severity.HIGH)

    metrics = verify_counterfactuals(report, _rerun)
    assert metrics.counterfactuals_evaluated == 1
    assert metrics.counterfactuals_removed_exactly == 0
    assert metrics.counterfactuals_severity_exact == 0
    assert metrics.counterfactual_failures, "a failed prediction must say why"


def test_counterfactual_verification_accepts_a_correct_prediction() -> None:
    capability = type("C", (), {"id": "cap-1"})()
    report = _stub_counterfactual_report(
        [capability],
        [
            CounterfactualResult(
                op=CounterfactualOp(kind="remove_tool", target_id="tool-x"),
                # The edit below removes cap-1, so the prediction must name it. An earlier version
                # of this fixture predicted an empty removal set while the re-run dropped the
                # capability, which is a *wrong* prediction: the engine removed something the
                # analysis never said it would. Set equality between the predicted removals and
                # the observed removals is what makes the check meaningful, so the fixture states
                # the truth rather than relaxing the check to match a contradiction.
                capabilities_removed=["cap-1"],
                severity_before=Severity.LOW,
                severity_after=Severity.LOW,
            )
        ],
    )

    def _rerun(_op: CounterfactualOp) -> AnalysisReport:
        return _stub_report([], Severity.LOW)

    metrics = verify_counterfactuals(report, _rerun)
    assert metrics.counterfactuals_removed_exactly == 1
    assert metrics.counterfactuals_severity_exact == 1
    assert not metrics.counterfactual_failures


def test_counterfactual_verification_records_a_failed_rerun() -> None:
    report = _stub_counterfactual_report(
        [],
        [CounterfactualResult(op=CounterfactualOp(kind="remove_tool", target_id="tool-x"))],
    )

    def _boom(_op: CounterfactualOp) -> AnalysisReport:
        raise RuntimeError("graph unavailable")

    metrics = verify_counterfactuals(report, _boom)
    assert metrics.counterfactuals_evaluated == 1
    assert "re-run failed" in metrics.counterfactual_failures[0]


# -------------------------------------------------------------- aggregate ----
def test_merge_scores_skips_scenarios_without_ground_truth() -> None:
    with_ground_truth = derive_scores(QualityMetrics(stateful_required=1, stateful_recalled=1))
    merged = merge_scores([with_ground_truth, derive_scores(QualityMetrics())])
    assert merged["stateful_recall"]["value"] == 1.0, "an unexercised scenario must not dilute"
    assert merged["stateful_recall"]["scenarios"] == 1


def test_merge_scores_of_nothing_is_empty() -> None:
    assert merge_scores([]) == {}


def test_merge_scores_preserves_efficiency_columns() -> None:
    merged = merge_scores([derive_scores(QualityMetrics(llm_calls=2, latency_ms=10))])
    assert merged["reasoning_efficiency"]["llm_calls"] == 2.0
    assert merged["reasoning_efficiency"]["latency_ms"] == 10.0


# ------------------------------------------------- regressions from the wired harness ----
# Each test below pins a defect found by actually running the metrics over the corpus. The shared
# lesson is that a metric which misdescribes the engine is worse than no metric, because the number
# gets believed.
def test_no_rate_can_exceed_one(registry: DataRegistry, scenarios: list[Scenario]) -> None:
    """A rate above 1.0 means the numerator and denominator came from different populations.

    Path recall once reported 1.37 because its numerator counted every *reported* capability while
    its denominator counted *expectations*. An impossible number in a headline table is a reliable
    signal that the metric is measuring the wrong thing, so it is asserted rather than eyeballed.
    """
    for scenario in scenarios:
        report, graph = _analyse(scenario, registry)
        scores = derive_scores(score_quality(scenario, report, graph))
        for name, value in scores.as_dict().items():
            if name in NON_RATE_FIELDS or not isinstance(value, float):
                continue
            # Both bounds matter. The upper one catches a numerator and a denominator drawn from
            # different populations; the lower one catches a rate that went negative, which no rate
            # can legitimately be -- and which the previous ``-1.0 <= value`` let through.
            assert 0.0 <= value <= 1.0, f"{scenario.id}: {name} = {value}"
        # Bound separately, because it is not a rate: a mean absolute error cannot be negative but
        # has no ceiling, so a depth error of 2 is a legitimate value rather than a broken metric.
        error = scores.mean_state_depth_error
        assert error is None or error >= 0.0, f"{scenario.id}: mean_state_depth_error = {error}"


def test_evidence_accuracy_is_measured_against_real_citations(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """Every capability the engine reports must be backed by evidence it can resolve.

    This scored 0.0 across all 13 scenarios, which looked like a catastrophic engine failure and was
    in fact a support predicate requiring the target resource to be named in the evidence text.
    Legitimate citations -- "tool-deploy exposes_action DEPLOY", "res-staging-api classification" --
    never name it, so every one was rejected. A metric reporting 0.0 for a healthy engine is
    indistinguishable from a broken one, which is why this is pinned.
    """
    scenario = _by_id(scenarios, "scenario-01")
    report, graph = _analyse(scenario, registry)
    metrics = score_quality(scenario, report, graph)
    assert derive_scores(metrics).evidence_accuracy == 1.0
    assert not metrics.unsupported_examples
    assert not metrics.dangling_examples


def test_agentic_claims_are_not_penalised_for_citing_their_hypothesis(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """An agentic capability's hypothesis item is its provenance, not a hallucination.

    The hallucination rate previously counted the agentic plane's *rejected* claims in the numerator,
    so a run scored 0.79 for catching bad proposals -- the metric rewarded the absence of scrutiny.
    It now counts accepted-but-ungrounded claims, and an agentic capability citing the hypothesis
    recording what it proposed, alongside the facts behind it, must score 0.0.
    """
    scenario = _by_id(scenarios, "scenario-06")
    report, _graph = _analyse(scenario, registry)
    metrics = score_quality(scenario, report, None)
    assert metrics.llm_claims_total > 0, "scenario-06 must exercise the agentic plane"
    assert metrics.llm_claims_ungrounded == 0, (
        f"ungrounded agentic claims: {metrics.llm_claims_ungrounded}/{metrics.llm_claims_total}"
    )
    assert derive_scores(metrics).hallucination_rate == 0.0


def test_counterfactual_sentences_are_not_scored_as_unfaithful(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """A counterfactual is verified by re-running the analysis, not by citing an evidence id.

    Counting them in explanation faithfulness reported 0.79 on runs whose counterfactual predictions
    verified cleanly, because those sentences were being asked for a citation they structurally
    cannot have. The finding/remediation distinction is now explicit in the narrative kinds.
    """
    scenario = _by_id(scenarios, "scenario-01")
    report, _graph = _analyse(scenario, registry)
    assert "remediation" in {statement.kind for statement in report.narrative}
    metrics = score_quality(scenario, report, None)
    assert not metrics.unsupported_sentences
    assert derive_scores(metrics).explanation_faithfulness == 1.0


def test_composition_and_stateful_families_derive_from_the_expectations(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """The two families that justify the agentic layer must actually be measured.

    Both reported "no ground truth" for the entire corpus because they were selected by scenario tag
    while the ground truth lives on the expectations themselves (``via`` naming two tools,
    ``min_state_depth``). A family that silently reports nothing looks identical to a perfect one in
    any average that ignores ``None``, so the derivation is asserted directly.
    """
    for prefix in ("scenario-06", "scenario-08"):
        scenario = _by_id(scenarios, prefix)
        report, graph = _analyse(scenario, registry)
        metrics = score_quality(scenario, report, graph)
        scores = derive_scores(metrics)
        assert scores.stateful_recall is not None, f"{prefix}: stateful recall is undefined"
        assert scores.stateful_recall == 1.0, f"{prefix}: stateful capability was not found"
        assert metrics.stateful_required >= 1

    composition = _by_id(scenarios, "scenario-06")
    report, graph = _analyse(composition, registry)
    assert derive_scores(score_quality(composition, report, graph)).composition_recall == 1.0


def test_every_reported_path_hop_is_a_real_graph_edge(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """The engine must not be able to assert an edge the environment does not contain.

    Capability paths were once assembled from a hard-coded template
    (``agent USES tool REQUIRES cred ASSUMES identity AUTHORIZES target``) in both the deterministic
    and the agentic plane. The template named edges the graph did not have -- half of every reported
    path failed verification -- which is precisely the fabrication path verification exists to catch,
    committed by the very engine being verified. Every hop is now read back out of the graph.
    """
    for scenario in scenarios:
        report, graph = _analyse(scenario, registry)
        # The aggregate first, through the public metric, so the invariant is stated in the terms the
        # scoring harness reports it; then the same invariant hop by hop so a failure names the edge.
        # The hop walk reuses the metric's own predicates deliberately: this test pins the property
        # score_quality measures, and sharing the predicates is what stops the two from disagreeing
        # about what counts as a real edge.
        metrics = score_quality(scenario, report, graph)
        assert metrics.path_hops_with_real_edge == metrics.path_hops, (
            f"{scenario.id}: {metrics.path_hops - metrics.path_hops_with_real_edge} of "
            f"{metrics.path_hops} reported hops are not real graph edges"
        )
        nx_graph = _as_nx(graph)
        for capability in report.capabilities:
            for source, relationship, destination in _path_edges(capability.path):
                assert _has_edge(nx_graph, source, destination, relationship), (
                    f"{scenario.id}: {capability.id} asserts a fabricated hop "
                    f"{source} -{relationship}-> {destination}"
                )


def test_every_narrative_citation_is_visible_in_the_report_text(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """The machine-checkable narrative and the human artifact must describe the same report."""
    for scenario in scenarios:
        report, _graph = _analyse(scenario, registry)
        assert report.report_text
        for statement in report.narrative:
            for citation in statement.evidence_ids:
                assert citation in report.report_text, (
                    f"{scenario.id}: {citation} is cited but not visible in the report text"
                )
