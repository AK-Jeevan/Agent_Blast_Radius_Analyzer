"""The metric families of docs/EVALUATION_PLAN.md §5, implemented as measurements.

:mod:`app.evaluation.metrics` scores the headline capability recall/precision/F1. This module
implements the remaining families: resource discovery, path discovery, tool-composition recall,
stateful accuracy, per-severity-band false positives/negatives, evidence accuracy, hallucination
rate, explanation faithfulness, counterfactual accuracy, contradiction accuracy, uncertainty
coverage, and reasoning efficiency.

Three rules keep these numbers auditable:

* **A metric with no ground truth reports ``None``, never 0.0.** A missing baseline is not a failure,
  and silently converting one into the other is how a report ends up claiming credit for a check
  nobody ran.
* **Everything is measured from the report artifact**, not from internal state, so a stored report
  can be re-scored later. That is the whole point of separating scoring from analysis.
* **Volatile fields are excluded from the determinism fingerprint.** Latency and the analysis id
  differ between any two runs by construction; the validity rule is about the *analysis*, not the
  clock.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from app.schemas.analysis import AnalysisReport, CounterfactualOp
from app.schemas.common import Relationship, Severity, severity_rank
from app.schemas.scenario import Scenario

#: Every relationship name a reported path may legitimately name between two hops.
RELATIONSHIP_NAMES = frozenset(item.value for item in Relationship)

#: Bands used for the per-band false-positive / false-negative rates. A HIGH false positive is a
#: different kind of wrong than an INFO one, so the plan requires them reported separately.
SEVERITY_BANDS: dict[str, tuple[Severity, ...]] = {
    "critical": (Severity.CRITICAL,),
    "high": (Severity.HIGH,),
    "medium": (Severity.MEDIUM,),
    "low": (Severity.LOW,),
    "info": (Severity.INFO,),
}

#: "High and above": the bands that must never be over-claimed.
HIGH_PLUS = ("critical", "high")


def band_of(severity: Severity) -> str:
    """The band a severity belongs to."""
    for name, members in SEVERITY_BANDS.items():
        if severity in members:
            return name
    return "info"


@dataclass
class QualityMetrics:
    """Raw counts for one report. Rates are derived in :func:`derive_scores`."""

    # resource discovery
    resources_reported: int = 0
    resources_expected: int = 0
    resource_hits: int = 0
    # capability
    capability_hits: int = 0
    capability_required: int = 0
    capability_forbidden_reported: int = 0
    # path discovery
    paths_reported: int = 0
    path_hops: int = 0
    path_hops_with_real_edge: int = 0
    paths_reconstructible: int = 0
    paths_expected: int = 0
    # composition and state
    composition_required: int = 0
    composition_recalled: int = 0
    stateful_required: int = 0
    stateful_recalled: int = 0
    state_depth_absolute_error: int = 0
    # per-band
    false_positives_by_band: dict[str, int] = field(default_factory=dict)
    false_negatives_by_band: dict[str, int] = field(default_factory=dict)
    reported_by_band: dict[str, int] = field(default_factory=dict)
    required_by_band: dict[str, int] = field(default_factory=dict)
    false_positive_labels: list[str] = field(default_factory=list)
    false_negative_labels: list[str] = field(default_factory=list)
    # evidence
    claims_checked: int = 0
    claims_fully_supported: int = 0
    dangling_citations: int = 0
    unsupported_claims: int = 0
    dangling_examples: list[str] = field(default_factory=list)
    unsupported_examples: list[str] = field(default_factory=list)
    # hallucination and injection
    llm_claims_total: int = 0
    llm_claims_rejected: int = 0
    llm_claims_ungrounded: int = 0
    injection_attempts: int = 0
    # explanation faithfulness
    narrative_sentences: int = 0
    narrative_sentences_cited: int = 0
    unsupported_sentences: list[str] = field(default_factory=list)
    # contradictions and uncertainties
    contradictions_expected: int = 0
    contradictions_matched: int = 0
    contradictions_unexpected: int = 0
    uncertainties_expected: int = 0
    uncertainties_reported: int = 0
    # counterfactuals (filled by verify_counterfactuals)
    counterfactuals_evaluated: int = 0
    counterfactuals_removed_exactly: int = 0
    counterfactuals_severity_exact: int = 0
    counterfactuals_without_unpredicted: int = 0
    counterfactual_failures: list[str] = field(default_factory=list)
    # reasoning efficiency
    llm_calls: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    estimated_cost_usd: float = 0.0
    steps_to_termination: int = 0
    caps_hit: list[str] = field(default_factory=list)


@dataclass
class QualityScores:
    """The rates derived from :class:`QualityMetrics`, with ``None`` for absent ground truth."""

    resource_precision: float | None
    resource_recall: float | None
    resource_f1: float | None
    capability_precision: float | None
    capability_recall: float | None
    capability_f1: float | None
    path_precision: float | None
    path_recall: float | None
    composition_recall: float | None
    stateful_recall: float | None
    mean_state_depth_error: float | None
    false_positive_rate_by_band: dict[str, float]
    false_negative_rate_by_band: dict[str, float | None]
    false_positive_rate_high_plus: float
    false_negative_rate_high_plus: float | None
    evidence_accuracy: float | None
    hallucination_rate: float | None
    explanation_faithfulness: float | None
    counterfactual_accuracy: float | None
    counterfactual_severity_accuracy: float | None
    counterfactual_no_unpredicted: float | None
    contradiction_precision: float | None
    contradiction_recall: float | None
    uncertainty_coverage: float | None
    reasoning_efficiency: dict[str, float]
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """Plain-data form, for the generated report and the JSON artifact."""
        return asdict(self)


def _f1(precision: float | None, recall: float | None) -> float | None:
    """F1 from two rates, or ``None`` when either is undefined."""
    if precision is None or recall is None or (precision + recall) == 0:
        return None
    return round(2 * precision * recall / (precision + recall), 4)


def _ratio(numerator: float, denominator: float) -> float | None:
    """A rate, or ``None`` when there is nothing to divide by (never 0.0 for 'no ground truth')."""
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def score_quality(
    scenario: Scenario,
    report: AnalysisReport,
    graph: Any | None = None,
) -> QualityMetrics:
    """Measure every §5 family for one scenario/report pair.

    ``graph`` is the built networkx graph. When supplied, path discovery verifies that each reported
    hop is a real edge; when it is not, path precision reports ``None`` rather than assuming the
    path is sound.
    """
    metrics = QualityMetrics()
    evidence_ids = {item.id for item in report.evidence}
    counted = [
        capability
        for capability in report.capabilities
        if capability.verification_status.value not in {"contradicted", "unverified"}
    ]
    reported_triples = {(item.action.value, item.target, item.environment) for item in counted}
    expected_triples = {
        (item.action.value, item.target, item.environment)
        for item in scenario.expectations.must_find_capabilities
    }
    forbidden_triples = {
        (item.action.value, item.target, item.environment)
        for item in scenario.expectations.must_not_find_capabilities
    }
    expectations = scenario.expectations

    # --- resource discovery -----------------------------------------------------
    expected_resources = {
        item.target
        for item in expectations.must_find_capabilities
        if item.target.startswith("res-")
    }
    metrics.resources_expected = len(expected_resources)
    metrics.resources_reported = len({item.target for item in counted})
    metrics.resource_hits = len(expected_resources & {item.target for item in counted})

    # --- capability and per-band rates -----------------------------------------
    metrics.capability_required = len(expectations.must_find_capabilities)
    metrics.capability_hits = len(reported_triples & expected_triples)
    metrics.capability_forbidden_reported = len(reported_triples & forbidden_triples)
    for triple in sorted(reported_triples & forbidden_triples):
        metrics.false_positive_labels.append(f"{triple[0]}->{triple[1]}@{triple[2]}")
    for triple in sorted(expected_triples - reported_triples):
        metrics.false_negative_labels.append(f"{triple[0]}->{triple[1]}@{triple[2]}")

    for name, band in SEVERITY_BANDS.items():
        metrics.reported_by_band[name] = sum(1 for item in counted if item.severity in band)
        expected_in_band = [
            item
            for item in expectations.must_find_capabilities
            if item.min_severity is not None and item.min_severity in band
        ]
        metrics.required_by_band[name] = len(expected_in_band)
        metrics.false_negatives_by_band[name] = sum(
            1
            for item in expected_in_band
            if (item.action.value, item.target, item.environment) not in reported_triples
        )
        metrics.false_positives_by_band[name] = sum(
            1
            for item in counted
            if item.severity in band
            and (item.action.value, item.target, item.environment) in forbidden_triples
        )

    # --- tool composition and stateful capability --------------------------------
    # These two families are the whole reason the agentic layer exists, so they are measured from the
    # scenario's own ground truth rather than inferred from tags alone:
    #
    #   * a *composed* capability is one whose expected chain names more than one tool -- no single
    #     tool accounts for the path, so the capability can only arise from composition;
    #   * a *stateful* capability is one declared with ``min_state_depth >= 1``, i.e. it is not
    #     available until something has been observed earlier in the session.
    #
    # Tag-based selection alone was tried first and silently produced "no ground truth" for both
    # families, which reads as a perfect score in any average that ignores ``None``. Deriving the
    # families from the expectations themselves means a scenario cannot be scored on a family it
    # never exercised, and cannot quietly opt out of one it did.
    for expectation in expectations.must_find_capabilities:
        tool_hops = {item for item in expectation.via if item.startswith("tool-")}
        match = _match_capability(counted, expectation)
        # ``derived_from`` counts as provenance: a derived capability (DESTROY, EXFILTRATE) records the
        # entities it was derived from there rather than in the path, because a path is a chain of graph
        # edges and these entities cannot be appended to it without inventing one.
        cited = (
            set(match.path) | set(match.provenance) | set(match.derived_from or [])
            if match is not None
            else set()
        )
        hop_ok = not expectation.via or bool(set(expectation.via) & cited)

        is_stateful = expectation.min_state_depth >= 1
        is_composed = len(tool_hops) >= 2

        if is_stateful:
            metrics.stateful_required += 1
            if match is not None and hop_ok and match.state_depth >= expectation.min_state_depth:
                metrics.stateful_recalled += 1
            elif match is not None:
                # Found, but not with the session state the ground truth requires. This is a
                # near-miss, and counting it as a plain miss would hide the distinction the family
                # exists to make, so the depth error is recorded separately.
                metrics.state_depth_absolute_error += abs(
                    match.state_depth - expectation.min_state_depth
                )
        if is_composed:
            metrics.composition_required += 1
            if match is not None and hop_ok:
                metrics.composition_recalled += 1

    # --- path discovery ---------------------------------------------------------
    # A graph the caller could not supply leaves the verified families undefined. Scoring an
    # unverifiable claim as 0.0 would read as "every reported path is fabricated", which is a very
    # different claim from "we did not check". The graph is always available inside the harness.
    nx_graph = _as_nx(graph)
    for capability in counted:
        if not capability.path:
            continue
        metrics.paths_reported += 1
        hops = _path_edges(capability.path)
        if nx_graph is None:
            # Without the graph the hops cannot be checked, so they are not counted at all. Counting
            # them with zero verified would report a precision of 0.0, which asserts that every
            # reported path is fabricated -- a very different and much stronger claim than "this run
            # did not verify paths", and one the data does not support.
            continue
        metrics.path_hops += len(hops)
        valid = sum(
            1
            for source, relationship, destination in hops
            if _has_edge(nx_graph, source, destination, relationship)
        )
        metrics.path_hops_with_real_edge += valid

    # Path *recall* is scored over the expectations, so its numerator and denominator come from the
    # same population. An earlier version counted the numerator over every reported capability while
    # the denominator counted expectations, which let recall exceed 1.0 whenever the report listed more
    # paths than the scenario expected -- an arithmetically impossible number that was quietly
    # averaging into the headline table.
    for expectation in expectations.must_find_capabilities:
        metrics.paths_expected += 1
        match = _match_capability(counted, expectation)
        if match is None or not match.path:
            continue
        cited = set(match.path) | set(match.provenance) | set(match.derived_from or [])
        if expectation.via and not (set(expectation.via) & cited):
            continue
        if nx_graph is None:
            # Without a graph the claim rests on the report's own provenance, which is what can
            # honestly be checked: the expected intermediate entities must appear in the chain.
            metrics.paths_reconstructible += 1
            continue
        hops = _path_edges(match.path)
        if (
            hops
            and match.target in match.path
            and all(
                _has_edge(nx_graph, source, destination, relationship)
                for source, relationship, destination in hops
            )
        ):
            metrics.paths_reconstructible += 1

    # --- evidence accuracy ------------------------------------------------------
    for capability in counted:
        metrics.claims_checked += 1
        dangling = [item for item in capability.evidence if item not in evidence_ids]
        unsupported = [
            item for item in capability.evidence if not _supports(item, capability, report)
        ]
        if dangling:
            metrics.dangling_citations += len(dangling)
            metrics.dangling_examples.append(
                f"{capability.action.value}->{capability.target}: {sorted(dangling)}"
            )
        if unsupported:
            metrics.unsupported_claims += 1
            metrics.unsupported_examples.append(
                f"{capability.action.value}->{capability.target}: {sorted(unsupported)}"
            )
        if not dangling and not unsupported:
            metrics.claims_fully_supported += 1

    # --- hallucination and injection -------------------------------------------
    # A hallucination is a claim that reached the report and should not have. Rejected claims are the
    # opposite: the verifier catching a bad proposal is the system working, and counting those as
    # hallucinations made a run score *worse* for being more suspicious. An earlier version computed
    # the rate as rejected/(rejected+accepted) and so reported 0.79 on a run with zero false
    # positives -- the metric was scoring the defence, not the failure.
    #
    # The numerator is therefore accepted agentic claims that no evidence supports, and the
    # denominator is every accepted claim the agentic layer contributed. Capabilities the
    # deterministic engine derived are excluded: the LLM did not author them, so counting them here
    # would misattribute the finding to the layer that did not cause it.
    metrics.llm_claims_rejected = len(report.agent_rejected_claims)
    metrics.injection_attempts = sum(
        1 for rejection in report.agent_rejected_claims if rejection.injection_signal
    )
    agentic_claims = [
        capability for capability in counted if capability.discovered_by != "deterministic"
    ]
    metrics.llm_claims_total = len(agentic_claims)
    metrics.llm_claims_ungrounded = sum(
        1
        for capability in agentic_claims
        if not capability.evidence
        or any(citation not in evidence_ids for citation in capability.evidence)
        or any(not _supports(citation, capability, report) for citation in capability.evidence)
    )

    # --- explanation faithfulness ----------------------------------------------
    # Faithfulness asks: does the sentence's claim rest on something the reader can inspect? Different
    # kinds of sentence are warranted in different ways, and scoring them all alike understated the
    # engine:
    #
    #   * *remediation* (counterfactual) sentences are verified by re-running the analysis with the
    #     edit applied (the counterfactual_accuracy family), not by citing an evidence id. There is no
    #     single pre-existing fact that "removing this tool removes 3 capabilities" rests on, because
    #     the sentence is itself the output of a computation.
    #   * *finding* and *explanation* sentences assert something about the environment, so they must
    #     cite evidence.
    #
    # Counting counterfactuals as unfaithful was a category error: it reported 0.79 on runs whose
    # counterfactual predictions verified cleanly, because those sentences were being asked for a
    # citation they structurally cannot have.
    statements = [item for item in report.narrative if item.kind != "remediation"]
    metrics.narrative_sentences = len(statements)
    for statement in statements:
        if [item for item in statement.evidence_ids if item in evidence_ids]:
            metrics.narrative_sentences_cited += 1
        else:
            metrics.unsupported_sentences.append(statement.text)

    # --- contradictions and uncertainties --------------------------------------
    found_codes = {item.code for item in report.contradictions}
    metrics.contradictions_expected = len(expectations.expected_contradictions)
    metrics.contradictions_matched = sum(
        1 for code in expectations.expected_contradictions if code in found_codes
    )
    metrics.contradictions_unexpected = len(found_codes - set(expectations.expected_contradictions))
    reported_codes = {item.code for item in report.uncertainties}
    reported_codes |= {
        code for capability in report.capabilities for code in capability.uncertainties
    }
    metrics.uncertainties_expected = len(expectations.expected_uncertainties)
    metrics.uncertainties_reported = sum(
        1 for code in expectations.expected_uncertainties if code in reported_codes
    )

    # --- reasoning efficiency ---------------------------------------------------
    run = report.metrics
    metrics.llm_calls = run.llm_calls
    metrics.tool_calls = run.tool_calls
    metrics.input_tokens = run.input_tokens
    metrics.output_tokens = run.output_tokens
    metrics.latency_ms = run.latency_ms
    metrics.estimated_cost_usd = run.estimated_cost_usd
    metrics.steps_to_termination = len(report.trajectory)
    metrics.caps_hit = list(run.caps_hit)
    return metrics


def _match_capability(counted: list[Any], expectation: Any) -> Any | None:
    """The reported capability answering one expectation, if any."""
    return next(
        (
            capability
            for capability in counted
            if capability.action == expectation.action
            and capability.target == expectation.target
            and (
                expectation.environment is None or capability.environment == expectation.environment
            )
        ),
        None,
    )


def _as_nx(graph: Any) -> Any | None:
    """Accept either the raw networkx graph or the ``EnvironmentGraph`` wrapper.

    Callers naturally hold one or the other depending on where they are, and path discovery should
    not care which. Returning ``None`` for anything else keeps the caller honest: a graph we cannot
    query yields an undefined path score rather than a falsely perfect one.
    """
    if graph is None:
        return None
    candidate = getattr(graph, "graph", graph)
    return candidate if hasattr(candidate, "has_edge") else None


def _path_edges(path: list[str]) -> list[tuple[str, str, str]]:
    """Split a reported path into ``(source, relationship, target)`` hops.

    Paths are stored *interleaved* -- ``[agent, "USES", tool, "REQUIRES", credential, ...]`` -- so the
    relationship label occupies the odd positions. Treating consecutive list entries as node pairs
    would compare a node against a relationship name, and every hop would appear fabricated. Both
    layouts are accepted so an older stored report still scores correctly.
    """
    if not path:
        return []
    odd_are_relations = all(item in RELATIONSHIP_NAMES for item in path[1::2])
    if odd_are_relations:
        return [
            (path[index], path[index + 1], path[index + 2]) for index in range(0, len(path) - 2, 2)
        ]
    return [(path[index], "", path[index + 1]) for index in range(0, len(path) - 1)]


def _has_edge(graph: Any, source: str, destination: str, relationship: str = "") -> bool:
    """Is there a real edge from ``source`` to ``destination`` (either direction)?

    When a relationship name is given it is matched against the edge attribute, so a path that claims
    ``USES`` is not satisfied by an edge that happens to be ``REQUIRES``.
    """
    for start, end in ((source, destination), (destination, source)):
        data = graph.get_edge_data(start, end)
        if not data:
            continue
        if not relationship:
            return True
        for attributes in data.values():
            if str(attributes.get("rel", "")).upper() == relationship.upper():
                return True
    return False


def verify_counterfactuals(
    report: AnalysisReport,
    rerun: Callable[[CounterfactualOp], AnalysisReport],
) -> QualityMetrics:
    """Score counterfactual accuracy by *re-running* the analysis with each edit applied.

    docs/EVALUATION_PLAN.md §5 defines three sub-checks, and all three need a second run:

    (a) removing edge set ``E`` removes exactly the predicted capabilities,
    (b) the predicted new severity equals the recomputed severity,
    (c) no capability appears that the counterfactual did not predict.

    A prediction that is never re-checked is an opinion, so this function is the only place
    counterfactual accuracy is allowed to come from.
    """
    metrics = QualityMetrics()
    baseline_ids = {item.id for item in report.capabilities}
    for predicted in report.counterfactuals:
        metrics.counterfactuals_evaluated += 1
        label = f"{predicted.op.kind}({predicted.op.target_id})"
        try:
            actual = rerun(predicted.op)
        except Exception as error:
            metrics.counterfactual_failures.append(f"{label}: re-run failed: {error}")
            continue
        actual_ids = {item.id for item in actual.capabilities}

        # (a) Did the edit remove exactly what was predicted? The prediction is checked as a set
        # comparison against what actually disappeared, not by intersecting with the surviving ids.
        # Intersecting would only catch a predicted id that still exists, which silently passes the
        # more important failure: a real capability that survived the edit while nothing predicted its
        # removal, and a predicted id that named nothing at all.
        predicted_removed = set(predicted.capabilities_removed)
        actually_removed = baseline_ids - actual_ids
        if predicted_removed == actually_removed:
            metrics.counterfactuals_removed_exactly += 1
        else:
            survived = sorted(actually_removed - predicted_removed)
            invented = sorted(predicted_removed - actually_removed)
            detail = []
            if survived:
                detail.append(f"still present after the edit: {survived}")
            if invented:
                detail.append(f"predicted removed but not present: {invented}")
            metrics.counterfactual_failures.append(
                f"{label}: removal prediction wrong ({'; '.join(detail)})"
            )
        if predicted.severity_after == actual.risk_summary.overall_severity:
            metrics.counterfactuals_severity_exact += 1
        else:
            metrics.counterfactual_failures.append(
                f"{label}: predicted severity {predicted.severity_after.value}, recomputed "
                f"{actual.risk_summary.overall_severity.value}"
            )
        added = actual_ids - baseline_ids
        if added <= set(predicted.capabilities_added):
            metrics.counterfactuals_without_unpredicted += 1
        else:
            metrics.counterfactual_failures.append(
                f"{label}: unpredicted capabilities appeared: "
                f"{sorted(added - set(predicted.capabilities_added))}"
            )
    return metrics


def derive_scores(metrics: QualityMetrics) -> QualityScores:
    """Turn raw counts into the rates of §5."""
    notes: list[str] = []
    resource_precision = _ratio(metrics.resource_hits, metrics.resources_reported)
    resource_recall = _ratio(metrics.resource_hits, metrics.resources_expected)
    if resource_recall is None:
        notes.append("resource discovery: the scenario declares no ground-truth resources")
    if metrics.paths_reported and metrics.path_hops == 0:
        notes.append("path discovery: reported paths contain no hops to verify")
    if metrics.uncertainties_reported < metrics.uncertainties_expected:
        notes.append(
            "uncertainty coverage: over-claiming is penalised; missing an expected uncertainty "
            "costs more than reporting an extra one"
        )

    capability_recall = _ratio(metrics.capability_hits, metrics.capability_required)
    capability_precision = _ratio(
        metrics.capability_hits, metrics.capability_hits + metrics.capability_forbidden_reported
    )

    def band_ratio(
        numerator: dict[str, int], denominator: dict[str, int], name: str
    ) -> float | None:
        """Rate for one band, treating an absent entry as zero counts."""
        return _ratio(numerator.get(name, 0), denominator.get(name, 0))

    # A band with nothing reported and nothing required is a zero false-positive rate: no claims
    # were made, so none were wrong. Bands with no ground truth report ``None`` instead.
    fp_by_band: dict[str, float] = {
        name: band_ratio(metrics.false_positives_by_band, metrics.reported_by_band, name) or 0.0
        for name in SEVERITY_BANDS
    }
    fn_by_band: dict[str, float | None] = {
        name: band_ratio(metrics.false_negatives_by_band, metrics.required_by_band, name)
        for name in SEVERITY_BANDS
    }
    high_plus_reported = sum(metrics.reported_by_band.get(name, 0) for name in HIGH_PLUS)
    high_plus_fp = sum(metrics.false_positives_by_band.get(name, 0) for name in HIGH_PLUS)
    high_plus_required = sum(metrics.required_by_band.get(name, 0) for name in HIGH_PLUS)
    high_plus_fn = sum(metrics.false_negatives_by_band.get(name, 0) for name in HIGH_PLUS)

    return QualityScores(
        resource_precision=resource_precision,
        resource_recall=resource_recall,
        resource_f1=_f1(resource_precision, resource_recall),
        capability_precision=capability_precision,
        capability_recall=capability_recall,
        capability_f1=_f1(capability_precision, capability_recall),
        path_precision=_ratio(metrics.path_hops_with_real_edge, metrics.path_hops),
        path_recall=_ratio(metrics.paths_reconstructible, metrics.paths_expected),
        composition_recall=_ratio(metrics.composition_recalled, metrics.composition_required),
        stateful_recall=_ratio(metrics.stateful_recalled, metrics.stateful_required),
        mean_state_depth_error=_ratio(
            metrics.state_depth_absolute_error, metrics.stateful_required
        ),
        false_positive_rate_by_band=fp_by_band,
        false_negative_rate_by_band=fn_by_band,
        false_positive_rate_high_plus=_ratio(high_plus_fp, high_plus_reported) or 0.0,
        false_negative_rate_high_plus=_ratio(high_plus_fn, high_plus_required),
        evidence_accuracy=_ratio(metrics.claims_fully_supported, metrics.claims_checked),
        hallucination_rate=_ratio(metrics.llm_claims_ungrounded, metrics.llm_claims_total),
        explanation_faithfulness=_ratio(
            metrics.narrative_sentences_cited, metrics.narrative_sentences
        ),
        counterfactual_accuracy=_ratio(
            metrics.counterfactuals_removed_exactly, metrics.counterfactuals_evaluated
        ),
        counterfactual_severity_accuracy=_ratio(
            metrics.counterfactuals_severity_exact, metrics.counterfactuals_evaluated
        ),
        counterfactual_no_unpredicted=_ratio(
            metrics.counterfactuals_without_unpredicted, metrics.counterfactuals_evaluated
        ),
        contradiction_precision=_ratio(
            metrics.contradictions_matched,
            metrics.contradictions_matched + metrics.contradictions_unexpected,
        ),
        contradiction_recall=_ratio(
            metrics.contradictions_matched, metrics.contradictions_expected
        ),
        uncertainty_coverage=_ratio(metrics.uncertainties_reported, metrics.uncertainties_expected),
        reasoning_efficiency={
            "llm_calls": float(metrics.llm_calls),
            "tool_calls": float(metrics.tool_calls),
            "input_tokens": float(metrics.input_tokens),
            "output_tokens": float(metrics.output_tokens),
            "latency_ms": float(metrics.latency_ms),
            "estimated_cost_usd": round(metrics.estimated_cost_usd, 6),
            "steps_to_termination": float(metrics.steps_to_termination),
            "caps_hit": float(len(metrics.caps_hit)),
        },
        notes=notes,
    )


def determinism_fingerprint(report: AnalysisReport) -> str:
    """A stable hash of the *analysis*, for the validity rule in §5.

    ``analysis_id``, ``report_text``, ``narrative``, latency, and cost differ between any two runs by
    construction, so including them would make every repeat look non-deterministic and the rule
    would be worthless.
    """
    payload = report.model_dump(mode="json", exclude={"analysis_id", "report_text", "narrative"})
    metrics = dict(payload.get("metrics") or {})
    for volatile in ("latency_ms", "estimated_cost_usd"):
        metrics.pop(volatile, None)
    payload["metrics"] = metrics
    serialised = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


def merge_scores(scores: list[QualityScores]) -> dict[str, Any]:
    """Aggregate per-scenario scores into one row of the evaluation table.

    Rates are averaged, and a scenario with no ground truth for a family is *skipped* rather than
    counted as zero â€” otherwise a scenario that never exercised, say, tool composition would
    silently halve the composition score. The number of contributing scenarios is reported next to
    each rate so the reader can see how thin a number is.
    """
    if not scores:
        return {}

    def mean(name: str) -> dict[str, float | int | None]:
        values = [getattr(item, name) for item in scores if getattr(item, name) is not None]
        if not values:
            return {"value": None, "scenarios": 0}
        return {"value": round(sum(values) / len(values), 4), "scenarios": len(values)}

    fp_bands = {
        name: round(
            sum(item.false_positive_rate_by_band.get(name, 0.0) for item in scores) / len(scores), 4
        )
        for name in SEVERITY_BANDS
    }
    fn_bands: dict[str, float | None] = {}
    for name in SEVERITY_BANDS:
        # The comprehension filters on `is not None`, but the type checker cannot narrow the element
        # type through a comprehension condition, so the cast is explicit. Summing the optionals
        # directly would also be a latent TypeError if the filter were ever changed without the cast.
        values = [
            value
            for value in (item.false_negative_rate_by_band.get(name) for item in scores)
            if value is not None
        ]
        fn_bands[name] = round(sum(values) / len(values), 4) if values else None

    efficiency = {
        key: round(sum(item.reasoning_efficiency.get(key, 0.0) for item in scores) / len(scores), 4)
        for key in scores[0].reasoning_efficiency
    }
    return {
        "resource_precision": mean("resource_precision"),
        "resource_recall": mean("resource_recall"),
        "resource_f1": mean("resource_f1"),
        "capability_precision": mean("capability_precision"),
        "capability_recall": mean("capability_recall"),
        "capability_f1": mean("capability_f1"),
        "path_precision": mean("path_precision"),
        "path_recall": mean("path_recall"),
        "composition_recall": mean("composition_recall"),
        "stateful_recall": mean("stateful_recall"),
        "mean_state_depth_error": mean("mean_state_depth_error"),
        "false_positive_rate_by_band": fp_bands,
        "false_negative_rate_by_band": fn_bands,
        "false_positive_rate_high_plus": round(
            sum(item.false_positive_rate_high_plus for item in scores) / len(scores), 4
        ),
        "false_negative_rate_high_plus": mean("false_negative_rate_high_plus"),
        "evidence_accuracy": mean("evidence_accuracy"),
        "hallucination_rate": mean("hallucination_rate"),
        "explanation_faithfulness": mean("explanation_faithfulness"),
        "counterfactual_accuracy": mean("counterfactual_accuracy"),
        "counterfactual_severity_accuracy": mean("counterfactual_severity_accuracy"),
        "counterfactual_no_unpredicted": mean("counterfactual_no_unpredicted"),
        "contradiction_precision": mean("contradiction_precision"),
        "contradiction_recall": mean("contradiction_recall"),
        "uncertainty_coverage": mean("uncertainty_coverage"),
        "reasoning_efficiency": efficiency,
        "notes": sorted({note for item in scores for note in item.notes}),
    }


def quality_of(
    report: AnalysisReport, scenario: Scenario, graph: Any | None = None
) -> QualityScores:
    """Convenience: measure and derive in one call."""
    return derive_scores(score_quality(scenario, report, graph))


def severity_at_least(severity: Severity, floor: Severity) -> bool:
    """Rank comparison, so callers do not have to import the rank helper themselves."""
    return severity_rank(severity) >= severity_rank(floor)


#: The scalar members of :class:`QualityScores`, in declaration order. Callers that receive scores as
#: plain data (the JSON artifact, the aggregated harness table) use this to rebuild a typed object
#: without guessing which keys belong to the dataclass and which are extra annotations merged in
#: afterwards. Listing them explicitly means a new family cannot be silently dropped by a round trip.
QUALITY_SCALAR_FAMILIES: tuple[str, ...] = (
    "resource_precision",
    "resource_recall",
    "resource_f1",
    "capability_precision",
    "capability_recall",
    "capability_f1",
    "path_precision",
    "path_recall",
    "composition_recall",
    "stateful_recall",
    "mean_state_depth_error",
    "false_positive_rate_by_band",
    "false_negative_rate_by_band",
    "false_positive_rate_high_plus",
    "false_negative_rate_high_plus",
    "evidence_accuracy",
    "hallucination_rate",
    "explanation_faithfulness",
    "counterfactual_accuracy",
    "counterfactual_severity_accuracy",
    "counterfactual_no_unpredicted",
    "contradiction_precision",
    "contradiction_recall",
    "uncertainty_coverage",
    "reasoning_efficiency",
    "notes",
)


__all__ = [
    "HIGH_PLUS",
    "QUALITY_SCALAR_FAMILIES",
    "SEVERITY_BANDS",
    "QualityMetrics",
    "QualityScores",
    "band_of",
    "derive_scores",
    "determinism_fingerprint",
    "merge_scores",
    "quality_of",
    "score_quality",
    "severity_at_least",
    "verify_counterfactuals",
]


def _supports(evidence_id: str, capability: Any, report: AnalysisReport) -> bool:
    """Is this evidence id actually about this capability, and is it a fact or inference?

    A citation that exists but describes a *different* subject is a supporting-looking citation, and
    counting it as support is exactly the failure mode evidence accuracy exists to catch.

    Support is judged against the capability's own chain, not against the target string alone. A
    capability is assembled from several entities -- the agent, the tool that exposes the action, the
    credential and identity it speaks as, the policy that permits it, and the resource it affects -- and
    a fact such as ``tool-deploy exposes_action DEPLOY`` is squarely supporting even though it never
    names the resource. An earlier version required the target to appear in the evidence text, which
    rejected every one of those legitimate citations and reported evidence accuracy as 0.0 across the
    whole corpus: a metric that was measuring its own predicate rather than the engine.

    Three checks, in order of directness:

    1. the item explicitly lists the capability among the things it ``supports``;
    2. the item names any entity in the capability's path or provenance;
    3. the item's text mentions the action, so a fact about the right verb is not dismissed.
    """
    item = next((entry for entry in report.evidence if entry.id == evidence_id), None)
    if item is None:
        return False
    if item.kind.value not in {"fact", "inference", "hypothesis"}:
        return False
    if capability.id in item.supports:
        return True

    # The entities the capability's own chain runs through. A path is stored interleaved with
    # relationship labels, so both are collected: naming a relationship is not evidence, but this is a
    # superset test and costs nothing.
    chain = {str(part).lower() for part in capability.path} | {
        str(part).lower() for part in capability.provenance
    }

    # A hypothesis that *supports* the capability is the correct provenance for an agentic claim, and
    # counts as support provided it is itself anchored to real evidence. Rejecting hypotheses made
    # evidence accuracy and the hallucination rate punish exactly the capabilities the agentic layer
    # exists to contribute: their hypothesis item is the record of what was proposed, so a claim citing
    # it alongside its supporting facts is properly grounded. This does not promote the claim to
    # *confirmed* -- that is the verifier's decision about ``verification_status``, a separate field.
    if item.kind.value == "hypothesis":
        return any(
            other.kind.value in {"fact", "inference"} and str(other.subject).lower() in chain
            for other in report.evidence
            if other.id in item.supports
        )

    # (2) Does the item name an entity the capability's chain runs through?
    if chain and str(item.subject).lower() in chain:
        return True
    if str(item.subject).lower() == str(capability.target).lower():
        return True

    # (3) Fall back to the text mentioning the target or the action.
    described = " ".join(
        part for part in (item.subject, item.predicate, item.object, item.note) if part
    ).lower()
    if capability.target.lower() in described:
        return True
    action = getattr(getattr(capability, "action", None), "value", "")
    return bool(action) and action.lower() in described
