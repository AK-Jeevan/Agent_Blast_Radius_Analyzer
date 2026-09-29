"""Authorization evaluator: deny-wins, globbing, credential binding, and verb strictness."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analyzers.authz import PolicyEvaluator
from app.schemas.analysis import AnalysisInput
from app.schemas.common import ActionClass
from app.services.loader import build_analysis_input, load_registry, load_scenarios

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def inputs_by_scenario() -> dict[str, AnalysisInput]:
    registry = load_registry()
    scenarios_dir = Path(__file__).resolve().parents[2] / "data" / "scenarios"
    return {
        scenario.id: build_analysis_input(registry, scenario)
        for scenario in load_scenarios(scenarios_dir)
    }


def test_qualified_verb_does_not_grant_the_bare_verb() -> None:
    """``read:logs`` must not authorize a general read (this once produced a phantom prod read)."""
    assert PolicyEvaluator._verb_matches("read:logs", "read") is False
    assert PolicyEvaluator._verb_matches("read", "read") is True
    assert PolicyEvaluator._verb_matches("*", "delete") is True
    assert PolicyEvaluator._verb_matches("write", "delete") is False


def test_explicit_deny_beats_any_allow(inputs_by_scenario: dict[str, AnalysisInput]) -> None:
    """S5: the deployment service may deploy to production, but the agent is denied it."""
    analysis_input: AnalysisInput = inputs_by_scenario["scenario-05-credential-discovery"]
    evaluator = PolicyEvaluator(analysis_input)
    prod_api = next(item for item in analysis_input.resources if item.id == "res-prod-api")

    allowed_for_service = evaluator.evaluate(
        ("ident-deploy-svc",), prod_api, ActionClass.DEPLOY, via_credential="cred-deploy-token"
    )
    assert allowed_for_service.allowed is True

    denied = evaluator.evaluate(
        ("ident-dev-agent", "ident-deploy-svc"),
        prod_api,
        ActionClass.DEPLOY,
        via_credential="cred-deploy-token",
    )
    assert denied.allowed is False
    assert denied.reason == "deny"
    assert "pol-dev-deny-prod" in denied.policies


def test_allow_is_bound_to_the_credential_used(
    inputs_by_scenario: dict[str, AnalysisInput],
) -> None:
    """A policy bound to one credential does not authorise calls made with a different one."""
    analysis_input = inputs_by_scenario["scenario-03-production-write"]
    evaluator = PolicyEvaluator(analysis_input)
    prod_db = next(item for item in analysis_input.resources if item.id == "res-prod-db")

    with_bound = evaluator.evaluate(
        ("ident-prod-writer",),
        prod_db,
        ActionClass.WRITE,
        via_credential="cred-prod-write",
    )
    with_wrong_credential = evaluator.evaluate(
        ("ident-prod-writer",),
        prod_db,
        ActionClass.WRITE,
        via_credential="cred-dev-token",
    )
    assert with_bound.allowed is True
    assert with_wrong_credential.allowed is False
    assert with_wrong_credential.reason == "no_matching_allow"


def test_default_deny_when_nothing_matches(inputs_by_scenario: dict[str, AnalysisInput]) -> None:
    analysis_input = inputs_by_scenario["scenario-11-adversarial-metadata"]
    evaluator = PolicyEvaluator(analysis_input)
    secret_store = next(item for item in analysis_input.resources if item.id == "res-secret-store")
    decision = evaluator.evaluate(
        ("ident-dev-agent",), secret_store, ActionClass.READ, via_credential="cred-dev-token"
    )
    assert decision.allowed is False
    assert decision.reason in {"deny", "no_matching_allow"}


def test_conditions_are_unknown_not_satisfied(inputs_by_scenario: dict[str, AnalysisInput]) -> None:
    """An unverifiable condition (source IP) must downgrade, never silently pass."""
    analysis_input = inputs_by_scenario["scenario-07-environment-boundary-violation"]
    evaluator = PolicyEvaluator(analysis_input)
    prod_api = next(item for item in analysis_input.resources if item.id == "res-prod-api")
    decision = evaluator.evaluate(
        ("ident-deploy-svc",), prod_api, ActionClass.DEPLOY, via_credential="cred-deploy-token"
    )
    assert decision.allowed is True
    assert decision.needs_downgrade is True
    assert any("source_ip_cidr" in label for label in decision.conditions_unknown)


def test_declared_authority_ignores_deny_and_reachability(
    inputs_by_scenario: dict[str, AnalysisInput],
) -> None:
    """Layer L0 is what the configuration *claims*, which is why it differs from the effective set."""
    analysis_input = inputs_by_scenario["scenario-05-credential-discovery"]
    evaluator = PolicyEvaluator(analysis_input)
    prod_api = next(item for item in analysis_input.resources if item.id == "res-prod-api")
    declared = evaluator.declared_actions(("ident-dev-agent", "ident-deploy-svc"), prod_api)
    assert ActionClass.DEPLOY in declared
    # ...while the same pair is denied for the agent's own principal.
    denied = evaluator.evaluate(
        ("ident-dev-agent", "ident-deploy-svc"),
        prod_api,
        ActionClass.DEPLOY,
        via_credential="cred-deploy-token",
    )
    assert denied.allowed is False


def test_resource_glob_matching(inputs_by_scenario: dict[str, AnalysisInput]) -> None:
    analysis_input = inputs_by_scenario["scenario-05-credential-discovery"]
    evaluator = PolicyEvaluator(analysis_input)
    prod_api = next(item for item in analysis_input.resources if item.id == "res-prod-api")
    assert evaluator._resource_matches(["res-prod-*"], prod_api) is True
    assert evaluator._resource_matches(["res-dev-*"], prod_api) is False
    assert evaluator._resource_matches(["production"], prod_api) is True
    assert evaluator._resource_matches(["*"], prod_api) is True
    assert evaluator._resource_matches(["prod-api"], prod_api) is True
    assert evaluator._resource_matches(["res-prod-db"], prod_api) is False
