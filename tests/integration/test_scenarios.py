"""End-to-end scenario tests: the engine must satisfy every scenario's ground truth.

These are the tests that make the project's central claim falsifiable. They run the *deterministic*
plane (mode A) across the whole corpus and assert:

* no forbidden capability is ever reported (false-positive guard);
* every required capability is found, except the ones the scenario itself predicts the baseline
  cannot see (the composition gap the agentic layer exists to close);
* severity never exceeds the scenario's ceiling;
* the same input produces an identical report (the determinism promise).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analyzers.engine import run_deterministic
from app.config import DATA_DIR, get_settings
from app.evaluation.metrics import score_scenario
from app.schemas.analysis import AnalysisReport
from app.schemas.common import RunMode, VerificationStatus, severity_rank
from app.schemas.scenario import Scenario
from app.services.loader import DataRegistry, build_analysis_input, load_registry, load_scenarios
from app.services.orchestrator import analyse

pytestmark = pytest.mark.integration

SCENARIOS_DIR = Path(DATA_DIR) / "scenarios"
COUNTED = {VerificationStatus.CONFIRMED, VerificationStatus.PROBABLE, VerificationStatus.POSSIBLE}


@pytest.fixture(scope="module")
def registry() -> DataRegistry:
    return load_registry()


@pytest.fixture(scope="module")
def scenarios() -> list[Scenario]:
    return load_scenarios(SCENARIOS_DIR)


@pytest.fixture(scope="module")
def results(
    registry: DataRegistry, scenarios: list[Scenario]
) -> dict[str, tuple[Scenario, AnalysisReport]]:
    """One deterministic run per scenario, reused across the assertions below."""
    return {
        scenario.id: (
            scenario,
            run_deterministic(
                build_analysis_input(registry, scenario, run_mode=RunMode.A_DETERMINISTIC)
            ),
        )
        for scenario in scenarios
    }


def test_corpus_covers_the_documented_scenario_set(
    results: dict[str, tuple[Scenario, AnalysisReport]],
) -> None:
    """The corpus must contain the ten documented scenarios plus the extra control cases."""
    ids = set(results)
    for index in range(1, 11):
        assert any(identifier.startswith(f"scenario-{index:02d}") for identifier in ids), index
    assert "scenario-10b-delete-irreversible" in ids
    assert "scenario-11-adversarial-metadata" in ids
    assert "scenario-12-mcp-metadata-untrusted" in ids


def test_no_forbidden_capability_is_ever_reported(
    results: dict[str, tuple[Scenario, AnalysisReport]],
) -> None:
    """The false-positive guard: the single most important assertion in the suite."""
    offenders: dict[str, list[str]] = {}
    for scenario_id, (scenario, report) in results.items():
        forbidden = [
            expectation.label
            for expectation in scenario.expectations.must_not_find_capabilities
            if any(
                capability.action == expectation.action
                and capability.target == expectation.target
                and (
                    expectation.environment is None
                    or capability.environment == expectation.environment
                )
                and capability.verification_status in COUNTED
                for capability in report.capabilities
            )
        ]
        if forbidden:
            offenders[scenario_id] = forbidden
    assert not offenders, f"false positives: {offenders}"


def test_required_capabilities_are_found_except_predicted_baseline_gaps(
    results: dict[str, tuple[Scenario, AnalysisReport]],
) -> None:
    """Every must_find is reported unless the scenario predicts the baseline cannot see it."""
    missing: dict[str, list[str]] = {}
    for scenario_id, (scenario, report) in results.items():
        predicted = set(scenario.expectations.expected_baseline_misses)
        for expectation in scenario.expectations.must_find_capabilities:
            found = any(
                capability.action == expectation.action
                and capability.target == expectation.target
                and (
                    expectation.environment is None
                    or capability.environment == expectation.environment
                )
                for capability in report.capabilities
            )
            if not found and expectation.label not in predicted:
                missing.setdefault(scenario_id, []).append(expectation.label)
    assert not missing, f"unexpected misses: {missing}"


def test_severity_never_exceeds_the_scenario_ceiling(
    results: dict[str, tuple[Scenario, AnalysisReport]],
) -> None:
    for scenario_id, (scenario, report) in results.items():
        ceiling = scenario.expectations.max_severity
        if ceiling is None:
            continue
        assert severity_rank(report.risk_summary.overall_severity) <= severity_rank(ceiling), (
            f"{scenario_id}: {report.risk_summary.overall_severity.value} exceeds {ceiling.value}"
        )


def test_reports_are_reproducible(registry: DataRegistry, scenarios: list[Scenario]) -> None:
    """The deterministic plane promises identical output for identical input."""
    scenario = next(item for item in scenarios if item.id.startswith("scenario-05"))
    analysis_input = build_analysis_input(registry, scenario)
    first = run_deterministic(analysis_input).model_dump(mode="json", exclude={"metrics"})
    second = run_deterministic(analysis_input).model_dump(mode="json", exclude={"metrics"})
    assert first == second


def test_declared_and_effective_layers_are_reported_separately(
    results: dict[str, tuple[Scenario, AnalysisReport]],
) -> None:
    """L0 and L2 must both be present; collapsing them is the failure mode we design against."""
    for scenario_id, (_scenario, report) in results.items():
        assert report.layers.effective_capability.capabilities == len(report.capabilities), (
            scenario_id
        )
        if report.layers.delta_notes:
            assert all(note.strip() for note in report.layers.delta_notes)


def test_network_isolation_yields_a_contradiction_not_a_finding(
    results: dict[str, tuple[Scenario, AnalysisReport]],
) -> None:
    """S9: declared production authority with no route must be a contradiction, not a capability."""
    _scenario, report = results["scenario-09-network-isolation"]
    assert not any(capability.target == "res-prod-db" for capability in report.capabilities)
    assert "AUTHORITY_UNREACHABLE" in {item.code for item in report.contradictions}


def test_recoverable_and_irreversible_deletions_are_distinguished(
    results: dict[str, tuple[Scenario, AnalysisReport]],
) -> None:
    """S10 vs S10b: the same delete action, different recoverability, different severity."""
    _recoverable, recoverable = results["scenario-10-delete-recoverable"]
    _irreversible, irreversible = results["scenario-10b-delete-irreversible"]
    assert not any(
        capability.action.value == "DESTROY" for capability in recoverable.capabilities
    ), "a documented backup means the deletion is not irreversible"
    destroy = [
        capability
        for capability in irreversible.capabilities
        if capability.action.value == "DESTROY"
    ]
    assert destroy, "removing the backup as well must yield a DESTROY capability"
    assert destroy[0].recoverability.value == "potentially_irreversible"
    assert destroy[0].severity.value == "CRITICAL"


def test_adversarial_metadata_does_not_create_capabilities(
    results: dict[str, tuple[Scenario, AnalysisReport]],
) -> None:
    """S11/S12: poisoned tool metadata and false authority claims change nothing."""
    for scenario_id in (
        "scenario-11-adversarial-metadata",
        "scenario-12-mcp-metadata-untrusted",
    ):
        _scenario, report = results[scenario_id]
        assert not any(
            capability.target in {"res-secret-store", "res-prod-db"}
            for capability in report.capabilities
        ), scenario_id
        assert report.injection_attempts, f"{scenario_id}: injection text must be reported"
        assert "MISLEADING_METADATA" in {item.code for item in report.contradictions}, scenario_id


def test_agentic_layer_closes_the_composition_gap(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """The project's existence proof, measured: mode D finds what mode A cannot.

    Uses the deterministic scripted client so the assertion is reproducible and free; the same code
    path is exercised against the real model with ``--real-llm``.
    """
    scenario = next(item for item in scenarios if item.id.startswith("scenario-06"))
    analysis_input = build_analysis_input(registry, scenario, run_mode=RunMode.D_FULL)
    settings = get_settings().model_copy(update={"llm_prefer_real": False})
    outcome = analyse(analysis_input, run_mode=RunMode.D_FULL, settings=settings)
    triples = {(item.action.value, item.target) for item in outcome.report.capabilities}
    assert ("DEPLOY", "res-prod-api") in triples, "the composed production deploy must be reported"
    agentic = [
        item for item in outcome.report.capabilities if item.discovered_by != "deterministic"
    ]
    assert agentic, "the capability must be attributed to the agentic layer"
    assert all(
        item.verification_status in {VerificationStatus.POSSIBLE, VerificationStatus.PROBABLE}
        for item in agentic
    ), "an agentic claim may never exceed PROBABLE"


def test_scoring_reports_no_errors_or_false_positives(
    results: dict[str, tuple[Scenario, AnalysisReport]],
) -> None:
    for scenario, report in results.values():
        scored = score_scenario(scenario, report)
        assert scored.error is None
        assert scored.false_positives == 0, f"{scenario.id}: {scored.false_positive_details}"
