"""Capability closure: the states the corpus cannot reach (docs/ANALYSIS_ENGINE_SPEC.md §1).

Every scenario in the corpus gives its agent a real edge to each tool it declares, grants at least one
policy, and reaches its targets over the network. That is what makes the integration sweep meaningful,
and it is also why several branches of the derivation are never exercised by it: a capability with no
provable path, a target the graph does not contain at all, a control a tool declared whose kind the
downgrade table does not know, and a state budget that was not the reason the iteration stopped. Each
test below constructs the state it needs, so a crash or a silently dropped control in one of them fails
loudly here rather than staying invisible to a green suite.
"""

from __future__ import annotations

import pytest

from app.analyzers.authz import PolicyEvaluator
from app.analyzers.closure import (
    ClosureResult,
    applicable_blockers,
    enriched_path,
    evaluate_preconditions,
    run_closure,
)
from app.analyzers.credentials import CredentialStatus, analyse_credentials
from app.analyzers.evidence import EvidenceLedger
from app.analyzers.reachability import ReachabilityAnalyzer
from app.config import DATA_DIR
from app.graph.builder import EnvironmentGraph, build_graph
from app.schemas.analysis import AnalysisInput
from app.schemas.common import ActionClass, RunMode
from app.schemas.entities import PreconditionKind, Tool
from app.schemas.scenario import Scenario
from app.services.loader import DataRegistry, build_analysis_input, load_registry, load_scenarios

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def registry() -> DataRegistry:
    return load_registry()


@pytest.fixture(scope="module")
def scenarios() -> list[Scenario]:
    return load_scenarios(DATA_DIR / "scenarios")


def _input(registry: DataRegistry, scenarios: list[Scenario], prefix: str) -> AnalysisInput:
    """The deterministic input for the one scenario whose id starts with ``prefix``."""
    scenario = next(item for item in scenarios if item.id.startswith(prefix))
    return build_analysis_input(registry, scenario, run_mode=RunMode.A_DETERMINISTIC)


def _tool(analysis_input: AnalysisInput, tool_id: str) -> Tool:
    return next(item for item in analysis_input.tools if item.id == tool_id)


def _closure(
    analysis_input: AnalysisInput,
    environment: EnvironmentGraph,
    *,
    max_state_depth: int = 4,
) -> ClosureResult:
    """Run the closure over a graph the caller has already built, so a test can edit it first."""
    return run_closure(
        analysis_input,
        environment,
        EvidenceLedger(),
        ReachabilityAnalyzer(environment),
        PolicyEvaluator(analysis_input),
        analyse_credentials(analysis_input),
        max_state_depth=max_state_depth,
    )


def _without_agent_tool_edges(
    analysis_input: AnalysisInput, environment: EnvironmentGraph
) -> EnvironmentGraph:
    """Drop every ``agent USES tool`` edge: the state in which no capability path is provable."""
    for tool in analysis_input.tools:
        if environment.graph.has_edge(analysis_input.agent.id, tool.id):
            environment.graph.remove_edge(analysis_input.agent.id, tool.id)
    return environment


def test_a_capability_with_no_provable_path_does_not_break_the_composite_pass(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """``enriched_path`` returns ``[]`` when the graph holds no agent->tool edge, and says so.

    The composite pass then named the subject of its inference with ``capability.path[0]``, so a
    capability in that documented state made the whole analysis raise ``IndexError`` instead of
    reporting the destruction it had already proved. The composite is a *stronger* claim than a
    primitive, which is exactly why it must not be the step that fails: the delete, and the backup
    that same tool can also delete, are derivable with or without a path.
    """
    analysis_input = _input(registry, scenarios, "scenario-10b")
    environment = _without_agent_tool_edges(analysis_input, build_graph(analysis_input))

    closure = _closure(analysis_input, environment)

    assert [item for item in closure.capabilities if not item.path], (
        "the derivation should keep a capability whose path cannot be proven"
    )
    derived = next(item for item in closure.capabilities if item.action == ActionClass.DESTROY)
    assert derived.path == []
    assert "res-prod-backups" in derived.derived_from


def test_a_target_the_graph_does_not_contain_yields_the_partial_chain(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """A target that was never materialised as a node is a missing route, not an exception.

    ``nx.shortest_path`` raises ``NodeNotFound`` for an endpoint the graph does not contain, and only
    ``NetworkXNoPath`` was caught, so a resource absent from the built graph turned a gap the report
    is supposed to state into a crash. The honest answer is the chain that *is* provable, stopping
    where the evidence stops.
    """
    analysis_input = _input(registry, scenarios, "scenario-01")
    environment = build_graph(analysis_input)
    tool = _tool(analysis_input, "tool-deploy")

    path = enriched_path(environment, analysis_input.agent.id, tool, None, None, "res-not-a-node")

    assert path[0] == analysis_input.agent.id
    assert path[-1] == tool.id, "an unprovable route must stop at the last real hop"
    assert "res-not-a-node" not in path


def test_a_declared_control_binds_even_when_its_kind_is_unrecognised(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """A control the tool names must not be discarded by a lookup keyed on its kind.

    ``tool-deploy`` declares ``blk-dryrun`` and the scenario lists it, but its kind (``dry_run``) has
    no entry in the downgrade table. Asking that table whether the control applied answered "no such
    kind", so a control the environment really does declare was dropped from the severity basis. Its
    environment scope is still honoured, which is the half of the test that must not be lost.
    """
    analysis_input = _input(registry, scenarios, "scenario-01")
    tool = _tool(analysis_input, "tool-deploy")
    assert "blk-dryrun" in tool.blockers

    assert "blk-dryrun" in applicable_blockers(analysis_input, tool, ActionClass.DEPLOY, "staging")
    assert applicable_blockers(analysis_input, tool, ActionClass.DEPLOY, "development") == []


def test_a_platform_control_scoped_to_one_environment_does_not_bind_in_another(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """Egress inspection applies in production, which is where the corpus scopes it.

    The composite pass asked whether *any* DLP control existed rather than whether one covered the
    target's environment, so a production-only control read as "egress is inspected everywhere" --
    the opposite of what a scoped control means.
    """
    analysis_input = _input(registry, scenarios, "scenario-02")
    tool = _tool(analysis_input, "tool-read-db")

    production = applicable_blockers(analysis_input, tool, ActionClass.READ, "production")
    staging = applicable_blockers(analysis_input, tool, ActionClass.READ, "staging")

    assert "blk-dlp-egress" in production
    assert "blk-dlp-egress" not in staging


def test_a_state_budget_that_did_not_stop_the_analysis_is_not_reported_as_hit(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """``max_state_depth=1`` reported MAX_STATE_DEPTH although nothing was left to discover.

    The flag came from the loop's ``else``, which fires when the range is exhausted rather than when
    work remains undone. Discovery is static, so one pass already reaches the fixpoint, and reporting
    truncation there told the reader the blast radius was understated when in fact it was complete. A
    budget of zero is still a genuine truncation, which is what keeps the flag meaningful rather than
    merely removed.
    """
    analysis_input = _input(registry, scenarios, "scenario-08")
    environment = build_graph(analysis_input)

    closure = _closure(analysis_input, environment, max_state_depth=1)
    assert closure.discovered, "the scenario must actually discover something for this to bite"
    assert "MAX_STATE_DEPTH" not in closure.caps_hit

    starved = _closure(analysis_input, environment, max_state_depth=0)
    assert starved.discovered == {}
    assert "MAX_STATE_DEPTH" in starved.caps_hit


def test_a_credential_precondition_for_another_credential_is_unknown_not_unmet(
    registry: DataRegistry, scenarios: list[Scenario]
) -> None:
    """An attempt made with a different credential does not prove the required one is absent.

    The precondition was reported ``False`` -- "unmet" -- whenever another credential was in use,
    which asserts a fact the analysis does not hold. Unmet and unproven are different claims and only
    the second is true here, so it is surfaced as an uncertainty instead.
    """
    analysis_input = _input(registry, scenarios, "scenario-01")
    tool = _tool(analysis_input, "tool-deploy")
    statuses = {item.credential.id: item for item in analyse_credentials(analysis_input)}
    required = next(
        item for item in tool.preconditions if item.kind == PreconditionKind.CREDENTIAL_PRESENT
    )
    unverified = f"precondition_unverified:{PreconditionKind.CREDENTIAL_PRESENT.value}"

    def _satisfied(status: CredentialStatus | None) -> bool | None:
        results, _ = evaluate_preconditions(tool, status, {}, "res-staging-api")
        return next(item.satisfied for item in results if item.kind == required.kind.value)

    assert _satisfied(statuses[required.ref]) is True
    assert _satisfied(None) is False

    other = next(item for item in statuses.values() if item.credential.id != required.ref)
    assert _satisfied(other) is None
    _, uncertainties = evaluate_preconditions(tool, other, {}, "res-staging-api")
    assert unverified in uncertainties
