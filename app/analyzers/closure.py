"""Capability closure: the deterministic derivation of what the agent can actually do.

This module implements docs/ANALYSIS_ENGINE_SPEC.md §1. It is deliberately LLM-free: the import rule
enforced by ``tests/unit/test_architecture.py`` forbids this package from importing ``app.agents``.

The algorithm, in order:

1. seed the evidence ledger with the facts the derivation will cite;
2. resolve credentials (obtainability, validity) and the principals they let the agent act as;
3. iterate state growth to a fixpoint: discovery tools reveal resources, state-gated tools can only
   address what has been discovered, and every iteration is recorded as ``state_depth``;
4. for every (tool, action, target, credential) candidate, decide internally:
   `exposed -> reachable -> authenticated -> authorized -> actionable`;
5. derive the composite actions ``EXFILTRATE`` and ``DESTROY``;
6. record contradictions, uncertainties, and blocked candidates as first-class outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from app.analyzers.authz import AuthzDecision, PolicyEvaluator
from app.analyzers.credentials import CredentialStatus
from app.analyzers.evidence import EvidenceLedger
from app.analyzers.reachability import ReachabilityAnalyzer, ReachabilityRecord
from app.analyzers.scoring import (
    assess_severity,
    blocker_applies,
    blocker_in_environment,
    recovery_for,
)
from app.analyzers.taxonomy import BLOCKER_SEVERITY_DOWNGRADE
from app.graph.builder import EnvironmentGraph
from app.schemas.analysis import (
    AnalysisInput,
    Capability,
    Contradiction,
    PreconditionResult,
    ReachabilityView,
    Uncertainty,
)
from app.schemas.common import (
    SENSITIVE_DATA_CLASSES,
    STATUS_CONFIDENCE_CEILING,
    ActionClass,
    Recoverability,
    Relationship,
    VerificationStatus,
    severity_rank,
    weakest_status,
)
from app.schemas.entities import PreconditionKind, Resource, Tool
from app.utils.ids import make_id, path_hash

#: Which relationship to report when the graph holds several parallel edges between the same pair.
#: Ordered most- to least-falsifiable: a concrete requirement beats a generic grant.
_PATH_RELATIONSHIP_PREFERENCE: tuple[str, ...] = (
    Relationship.REQUIRES.value,
    Relationship.DISCOVERS.value,
    Relationship.ASSUMES.value,
    Relationship.USES.value,
    Relationship.AUTHORIZES.value,
    Relationship.HAS_ACCESS_TO.value,
    Relationship.CONNECTS_TO.value,
)

#: Status weight used by the confidence formula.
_STATUS_WEIGHT: dict[VerificationStatus, float] = {
    VerificationStatus.CONFIRMED: 1.00,
    VerificationStatus.PROBABLE: 0.75,
    VerificationStatus.POSSIBLE: 0.50,
    VerificationStatus.UNVERIFIED: 0.35,
    VerificationStatus.CONTRADICTED: 0.10,
}


@dataclass(frozen=True)
class BlockedCandidate:
    """A pair that *could* be a capability but fails one specific internal test.

    Blocked candidates are what let the report show "declared but not effective" instead of silently
    dropping the difference.
    """

    tool_id: str
    action: ActionClass
    target: str
    reason: str
    detail: str = ""
    evidence: tuple[str, ...] = ()


@dataclass
class ClosureResult:
    """Everything the deterministic planner derived, ready for scoring and reporting."""

    capabilities: list[Capability] = field(default_factory=list)
    capability_evidence: dict[str, list[str]] = field(default_factory=dict)
    declared_pairs: list[tuple[ActionClass, str, str | None]] = field(default_factory=list)
    reachable_pairs: list[tuple[ActionClass, str, str | None]] = field(default_factory=list)
    blocked: list[BlockedCandidate] = field(default_factory=list)
    contradictions: list[Contradiction] = field(default_factory=list)
    uncertainties: list[Uncertainty] = field(default_factory=list)
    discovered: dict[str, int] = field(default_factory=dict)
    credential_statuses: list[CredentialStatus] = field(default_factory=list)
    caps_hit: list[str] = field(default_factory=list)


def is_state_gated(tool: Tool) -> bool:
    """True when a tool can only address endpoints discovered earlier in the session."""
    return any(
        precondition.kind == PreconditionKind.SESSION_FACT for precondition in tool.preconditions
    )


def candidate_targets(
    tool: Tool, resources: list[Resource], discovered: dict[str, int]
) -> list[str]:
    """Which resources this tool can address, given the current session state."""
    in_scope = {resource.id for resource in resources}
    targets = set(tool.targets) & in_scope
    if is_state_gated(tool):
        targets |= set(discovered) & in_scope
    elif not tool.target_selector.closed_vocabulary:
        # A free-form target parameter really can address anything in scope; the check that follows
        # (authorization + reachability) is what keeps this honest.
        targets |= in_scope
    if tool.discovery_capability:
        targets |= set(discovered) & in_scope
    return sorted(targets)


#: Control kinds that belong to the *platform* (apply by environment and action) rather than to a
#: specific tool. An approval gate or egress inspection is not a property of a tool.
PLATFORM_BLOCKER_KINDS: frozenset[str] = frozenset(
    {"approval_gate", "dlp", "rate_limit", "network_policy"}
)


def applicable_blockers(
    analysis_input: AnalysisInput,
    tool: Tool,
    action: ActionClass,
    target_environment: str | None,
) -> list[str]:
    """Blocker ids that gate this action against this target.

    Platform controls apply whenever their environment and action match; tool-attached controls only
    apply when the tool declares them. This is why a production approval gate cannot be escaped just
    because a tool forgot to mention it.
    """
    tool_attached = set(tool.blockers)
    applicable: list[str] = []
    for blocker in analysis_input.blockers:
        if blocker.id in tool_attached:
            # A tool-attached control is matched by id, not by kind. Passing it through
            # ``blocker_applies`` would ask the downgrade table whether its *kind* has an effect, and
            # a kind that table does not list -- ``dry_run`` is one, and tool-deploy in the corpus
            # declares ``blk-dryrun`` -- has no entry to consult. The control the tool explicitly
            # named was therefore dropped by the very check that was supposed to admit it. Where the
            # kind *is* known its action scope is still honoured, so a declared read-masking control
            # cannot be made to downgrade a delete. Environment scope is a property of the control
            # itself rather than of its kind, so it always applies.
            if not blocker_in_environment(blocker.environments, target_environment):
                continue
            affected = BLOCKER_SEVERITY_DOWNGRADE.get(blocker.kind.value)
            if affected is not None and action.value not in affected:
                continue
            applicable.append(blocker.id)
            continue
        if blocker.kind.value in PLATFORM_BLOCKER_KINDS and blocker_applies(
            blocker.kind.value, action, target_environment, blocker.environments
        ):
            applicable.append(blocker.id)
    return sorted(set(applicable))


def control_kinds(analysis_input: AnalysisInput, blocker_ids: list[str]) -> list[str]:
    """Blocker kinds in scope, used for severity adjustment and reporting."""
    wanted = set(blocker_ids)
    return sorted(
        {blocker.kind.value for blocker in analysis_input.blockers if blocker.id in wanted}
    )


def seed_evidence(analysis_input: AnalysisInput, ledger: EvidenceLedger) -> dict[str, list[str]]:
    """Record the base facts and index them by entity id so capabilities can cite them.

    Facts come only from structured input. Untrusted sources are recorded as inferences by the ledger
    itself, which is what keeps "the tool description says so" out of the fact count.
    """
    index: dict[str, list[str]] = {}

    def record(entity_id: str, evidence_id: str) -> None:
        index.setdefault(entity_id, []).append(evidence_id)

    agent = analysis_input.agent
    record(
        agent.id,
        ledger.fact(
            agent.id,
            "runs_as",
            obj=agent.identity,
            source=agent.source,
            note=f"declared environment={agent.environment}",
        ),
    )
    if analysis_input.identity is not None:
        identity = analysis_input.identity
        record(
            identity.id,
            ledger.fact(
                identity.id,
                "identity_type",
                value={"type": identity.type.value, "provider": identity.provider.value},
                source=identity.source,
                note=f"environment={identity.environment}",
            ),
        )
    if analysis_input.environment is not None:
        environment = analysis_input.environment
        record(
            environment.id,
            ledger.fact(
                environment.id,
                "tier",
                value={"tier": environment.tier.value, "criticality": environment.criticality},
                source=environment.source,
            ),
        )
    for tool in analysis_input.tools:
        for item in tool.action_evidence:
            record(
                tool.id,
                ledger.fact(
                    tool.id,
                    "exposes_action",
                    obj=item.action.value,
                    value={"method": item.method.value, "confidence": item.method_confidence},
                    source=tool.source,
                    note=item.span or item.notes,
                ),
            )
    for credential in analysis_input.credentials:
        record(
            credential.id,
            ledger.fact(
                credential.id,
                "scope",
                value={
                    "scope": list(credential.scope),
                    "permissions": list(credential.permissions),
                },
                source=credential.source,
                note=f"expires_at={credential.expires_at}",
            ),
        )
        if credential.assumed_identity:
            record(
                credential.id,
                ledger.fact(
                    credential.id,
                    "assumes_identity",
                    obj=credential.assumed_identity,
                    source=credential.source,
                ),
            )
    for edge in analysis_input.network:
        record(
            edge.id,
            ledger.fact(
                edge.from_id,
                "connects_to",
                obj=edge.target,
                value={
                    "reachable": edge.reachable,
                    "protocol": edge.protocol,
                    "egress": edge.egress.value,
                },
                polarity=edge.reachable,
                source=edge.source,
                note=edge.evidence_note,
            ),
        )
    for resource in analysis_input.resources:
        record(
            resource.id,
            ledger.fact(
                resource.id,
                "classification",
                obj=resource.environment,
                value={
                    "data_class": resource.data_class.value,
                    "criticality": resource.criticality,
                    "type": resource.type.value,
                },
                source=resource.source,
            ),
        )
        if resource.recovery is not None:
            record(
                resource.id,
                ledger.fact(
                    resource.id,
                    "recovery",
                    value={
                        "recoverability": resource.recovery.recoverability.value,
                        "mechanisms": list(resource.recovery.mechanisms),
                        "latest_recovery_point": resource.recovery.latest_recovery_point,
                    },
                    source=resource.source,
                ),
            )
        for backup in resource.backs_up:
            record(
                backup,
                ledger.fact(
                    resource.id,
                    "backs_up",
                    obj=backup,
                    source=resource.source,
                    note="recovery mechanism for the target resource",
                ),
            )
    for policy in analysis_input.permissions:
        record(
            policy.id,
            ledger.fact(
                policy.id,
                "policy_effect",
                obj=",".join(policy.actions),
                value={
                    "effect": policy.effect,
                    "actions": list(policy.actions),
                    "resources": list(policy.resources),
                    "via": policy.via,
                    "conditions": [condition.kind.value for condition in policy.conditions],
                },
                polarity=policy.effect == "allow",
                source=policy.source,
                note=policy.evidence_note,
            ),
        )
        record(policy.principal, index[policy.id][-1])
    return index


def confidence_for(
    evidence_ids: list[str], status: VerificationStatus, ledger: EvidenceLedger
) -> float:
    """Deterministic confidence: computed from evidence, capped by status, never self-asserted."""
    facts = ledger.fact_count(evidence_ids)
    facts_factor = min(1.0, facts / 3.0)
    base = 0.45 * _STATUS_WEIGHT[status] + 0.45 * facts_factor + 0.10
    return float(min(round(base, 3), STATUS_CONFIDENCE_CEILING[status]))


def _relay_rel(environment: EnvironmentGraph, source: str, destination: str) -> str:
    """A real relationship label for ``source -> destination``, or "" when the graph has no such edge.

    When the graph holds several parallel edges between the same pair the most specific wins, since
    "this tool needs this credential" (REQUIRES) is a stronger, more falsifiable claim than "these
    two are merely connected" (HAS_ACCESS_TO / CONNECTS_TO).
    """
    data = environment.graph.get_edge_data(source, destination)
    if not data:
        return ""
    candidates = [str(attributes.get("rel", "")) for attributes in data.values()]
    for preferred in _PATH_RELATIONSHIP_PREFERENCE:
        if preferred in candidates:
            return preferred
    return next((name for name in candidates if name), "")


def enriched_path(
    environment: EnvironmentGraph,
    agent_id: str,
    tool: Tool,
    credential_id: str | None,
    assumed_identity: str | None,
    target: str,
) -> list[str]:
    """The capability path: only the edges the graph can actually prove.

    This used to be a hard-coded template (``agent USES tool REQUIRES cred ASSUMES identity
    AUTHORIZES target``), which meant the report could assert edges the environment does not
    contain -- the exact fabrication that path verification exists to catch, so the engine was
    grading its own homework. It also told the wrong story whenever a credential was obtained by a
    different tool than the one that later used it.

    Each candidate hop is now checked against the graph and kept only if a real edge exists, so every
    relationship in the rendered path is falsifiable. Hops must also be *contiguous*: a hop is only
    rendered when its source is the entity the chain currently ends on, because otherwise the path
    would show ``tool ASSUMES identity`` for what the graph actually says is
    ``credential ASSUMES identity`` -- a true edge attributed to the wrong subject.

    Not every tool can reach its target by a direct edge. A tool that acts on a resource it did not
    itself enumerate (discovered earlier in the session through a different tool) is reached through
    that discovery chain, so when the direct walk stalls the shortest real path from the agent to the
    target is used instead. If the graph contains no such route the partial chain is returned, which
    is honest: it says what is provable and stops.
    """
    opening = _relay_rel(environment, agent_id, tool.id)
    if not opening:
        # Without a real agent->tool edge there is no capability chain to report at all.
        return []

    # Ordered by analytical interest: the credential and identity hops explain *how* the agent acts,
    # so they are attempted before the direct tool->target hop, which is the bare-minimum fallback.
    attempts = (
        (tool.id, credential_id),
        (credential_id, assumed_identity),
        (assumed_identity, target),
        (tool.id, target),
    )
    path: list[str] = [agent_id, opening, tool.id]
    tail = tool.id
    for source, destination in attempts:
        if not source or not destination or source != tail:
            # Not contiguous: this edge exists, but rendering it here would attach it to the wrong
            # subject, so it is only usable below as part of a genuine route to the target.
            continue
        relationship = _relay_rel(environment, source, destination)
        if not relationship:
            continue
        path.extend([relationship, destination])
        tail = destination
    if target in path:
        return path

    # The direct chain stalled short of the target. Fall back to the shortest route the graph really
    # contains (typically agent USES <discovering tool> DISCOVERS <resource>), so the path still
    # terminates on the affected resource.
    route = _shortest_route(environment, agent_id, target)
    if route:
        return route
    return path


def _shortest_route(
    environment: EnvironmentGraph,
    source: str,
    target: str,
) -> list[str]:
    """The shortest real edge path ``source -> target``, interleaved with relationship labels.

    Returns ``[]`` when the graph holds no such route. Every hop is re-checked against the graph
    before it is emitted, so this cannot introduce an edge that ``enriched_path`` would have rejected.
    """
    if source == target:
        return [source]
    try:
        # ``shortest_path`` is a module-level networkx function, not a MultiDiGraph method, so it has
        # to be called through the library. NetworkXNoPath is the normal "nothing connects these"
        # answer and is deliberately not an error. NodeNotFound is the same answer for an endpoint the
        # graph does not contain at all: a target that was never materialised as a node is a missing
        # route, not a programming error, and letting it propagate turned a reportable gap into a
        # crash.
        nodes = nx.shortest_path(environment.graph, source, target)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []
    if not nodes or nodes[0] != source or nodes[-1] != target:
        return []
    path: list[str] = [source]
    for index in range(len(nodes) - 1):
        relationship = _relay_rel(environment, nodes[index], nodes[index + 1])
        if not relationship:
            return []
        path.extend([relationship, nodes[index + 1]])
    return path


def evaluate_preconditions(
    tool: Tool,
    credential_status: CredentialStatus | None,
    discovered: dict[str, int],
    target: str,
) -> tuple[list[PreconditionResult], list[str]]:
    """Evaluate tool preconditions and return them together with any uncertainty codes."""
    results: list[PreconditionResult] = []
    uncertainties: list[str] = []
    for precondition in tool.preconditions:
        satisfied: bool | None = None
        if precondition.kind == PreconditionKind.CREDENTIAL_PRESENT:
            if credential_status is None:
                # No credential is being used on this attempt, so the required one is demonstrably
                # absent.
                satisfied = False
            elif credential_status.id == precondition.ref:
                satisfied = True
            else:
                # A *different* credential is in use. Reporting the required one as absent would
                # assert a fact the analysis does not hold: this attempt did not use it, which is not
                # the same as it being unobtainable. The precondition stays unknown and is surfaced as
                # an uncertainty, matching how reachability treats a credential it cannot prove.
                satisfied = None
        elif precondition.kind == PreconditionKind.SESSION_FACT:
            satisfied = target in discovered or precondition.ref in discovered
        elif precondition.kind == PreconditionKind.RESOURCE_EXISTS:
            satisfied = True
        if satisfied is None:
            uncertainties.append(f"precondition_unverified:{precondition.kind.value}")
        results.append(
            PreconditionResult(
                kind=precondition.kind.value,
                ref=precondition.ref,
                satisfied=satisfied,
                note=precondition.note,
            )
        )
    return results, uncertainties


def run_closure(
    analysis_input: AnalysisInput,
    environment: EnvironmentGraph,
    ledger: EvidenceLedger,
    reachability: ReachabilityAnalyzer,
    evaluator: PolicyEvaluator,
    credential_statuses: list[CredentialStatus],
    *,
    max_state_depth: int = 4,
) -> ClosureResult:
    """Derive declared, reachable, and effective authority for one agent environment."""
    result = ClosureResult(credential_statuses=list(credential_statuses))
    index = seed_evidence(analysis_input, ledger)
    reach = reachability.records()
    resources = sorted(analysis_input.resources, key=lambda item: item.id)
    resources_by_id = {resource.id: resource for resource in resources}
    identity = analysis_input.identity
    identity_id = identity.id if identity is not None else analysis_input.agent.id
    usable = [status for status in credential_statuses if status.usable]
    obtainable = [status for status in credential_statuses if status.present or status.indirect]
    declared_principals = tuple(
        sorted({identity_id} | {s.assumed_identity for s in obtainable if s.assumed_identity})
    )

    # --- L0: declared authority (ignores deny, via-binding, conditions, and reachability) -----
    for resource in resources:
        for action in evaluator.declared_actions(declared_principals, resource):
            result.declared_pairs.append((action, resource.id, resource.environment))

    # --- state growth: iterate discovery to a fixpoint ----------------------------------------
    discovered: dict[str, int] = {}

    def undiscovered_in_scope() -> set[str]:
        """Resources some discovery-capable tool can reveal that the session has not seen yet."""
        return {
            resource_id
            for tool in analysis_input.tools
            for resource_id in tool.discovery_capability
            if resource_id in resources_by_id and resource_id not in discovered
        }

    for depth in range(1, max_state_depth + 1):
        for resource_id in sorted(undiscovered_in_scope()):
            discovered[resource_id] = depth
        # The budget was not the reason the iteration stopped if nothing is left to discover, so the
        # cap is reported only when work genuinely remains undone. The old ``for ... else`` fired
        # whenever the range ran out, which meant ``max_state_depth=1`` reported MAX_STATE_DEPTH even
        # though that single pass had already found everything discoverable: discovery is static
        # (``tool.discovery_capability`` is a fixed property of the tool), so no pass after the first
        # can learn anything new, and ``state_depth`` is therefore 0 or 1 by construction.
        if not undiscovered_in_scope():
            break
    else:
        result.caps_hit.append("MAX_STATE_DEPTH")
    result.discovered = dict(discovered)

    if not analysis_input.network:
        result.uncertainties.append(
            Uncertainty(
                id=make_id("uncertainty", "insufficient_input", "network"),
                code="insufficient_input",
                message=(
                    "No network section was supplied, so reachability is UNKNOWN rather than denied."
                ),
                affects=[],
            )
        )

    # --- L1: reachable authority (authorized and reachable, ignoring tool expressiveness) -----
    for resource in resources:
        record = reach.get(resource.id)
        if record is None or not record.reachable:
            continue
        for action, _resource_id, _env in list(result.declared_pairs):
            if _resource_id != resource.id:
                continue
            if any(
                evaluator.evaluate(
                    (identity_id, status.assumed_identity or identity_id),
                    resource,
                    action,
                    via_credential=status.id,
                ).allowed
                for status in usable
            ):
                result.reachable_pairs.append((action, resource.id, resource.environment))

    return _derive_capabilities(
        analysis_input=analysis_input,
        environment=environment,
        ledger=ledger,
        evaluator=evaluator,
        reach=reach,
        reachability=reachability,
        result=result,
        index=index,
        resources=resources,
        resources_by_id=resources_by_id,
        identity_id=identity_id,
        usable=usable,
        obtainable=obtainable,
    )


def _credential_findings(
    result: ClosureResult, obtainable: list[CredentialStatus], index: dict[str, list[str]]
) -> None:
    """Record expiry/invalidity contradictions and obtainability uncertainties."""
    for status in obtainable:
        credential = status.credential
        credential_evidence = list(index.get(credential.id, []))
        if status.expiry_state == "expired":
            result.contradictions.append(
                Contradiction(
                    id=make_id("contradiction", "CREDENTIAL_EXPIRED", credential.id),
                    code="CREDENTIAL_EXPIRED",
                    subject=credential.id,
                    message=(
                        f"{credential.id} is referenced by policy but expired at "
                        f"{credential.expires_at}: the declared authority is not usable."
                    ),
                    sides={"declared": credential_evidence, "effective": credential_evidence[:1]},
                    evidence=credential_evidence,
                    severity_impact="authority_unusable",
                )
            )
        elif status.expiry_state == "unknown":
            result.uncertainties.append(
                Uncertainty(
                    id=make_id("uncertainty", "credential_expiry_unknown", credential.id),
                    code="credential_expiry_unknown",
                    message=f"{credential.id} has no declared expiry, so its validity is unconfirmed.",
                    affects=[credential.id],
                    source_ref=credential.source.ref,
                )
            )
        if status.indirect:
            result.uncertainties.append(
                Uncertainty(
                    id=make_id("uncertainty", "credential_discovered_indirectly", credential.id),
                    code="credential_discovered_indirectly",
                    message=(
                        f"{credential.id} was never granted to this agent, but "
                        f"{', '.join(status.obtained_via)} can read it from the workspace."
                    ),
                    affects=[credential.id],
                    source_ref=credential.source.ref,
                )
            )


def _derive_capabilities(
    *,
    analysis_input: AnalysisInput,
    environment: EnvironmentGraph,
    ledger: EvidenceLedger,
    evaluator: PolicyEvaluator,
    # The real type is ReachabilityRecord, not `object`. Widening to `object` erased the type from
    # every downstream access, so `reach_record.authenticated_for(...)` and the record's fields became
    # invisible to a type checker even though they are always a ReachabilityRecord here (`records()`
    # returns exactly that). Naming the type costs nothing and keeps the accesses checkable.
    reach: dict[str, ReachabilityRecord],
    reachability: ReachabilityAnalyzer,
    result: ClosureResult,
    index: dict[str, list[str]],
    resources: list[Resource],
    resources_by_id: dict[str, Resource],
    identity_id: str,
    usable: list[CredentialStatus],
    obtainable: list[CredentialStatus],
) -> ClosureResult:
    """Iterate tools, actions, targets, and credentials, deciding each candidate internally."""
    agent_id = analysis_input.agent.id
    agent_environment = (
        analysis_input.environment.name
        if analysis_input.environment is not None
        else analysis_input.agent.environment
    )
    seen: dict[tuple[str, str, str | None], Capability] = {}
    _credential_findings(result, obtainable, index)

    for tool in sorted(analysis_input.tools, key=lambda item: item.id):
        targets = candidate_targets(tool, resources, result.discovered)
        tool_evidence = list(index.get(tool.id, []))
        for action in sorted(tool.actions, key=lambda item: item.value):
            if action == ActionClass.DISCOVER:
                continue
            for target_id in targets:
                resource = resources_by_id[target_id]
                state_depth = (
                    0 if target_id in set(tool.targets) else result.discovered.get(target_id, 0)
                )
                candidates = (
                    [item for item in usable if item.id in set(tool.requires_credentials)]
                    if tool.requires_credentials
                    else list(usable)
                )
                if tool.requires_credentials and not candidates:
                    result.blocked.append(
                        BlockedCandidate(
                            tool_id=tool.id,
                            action=action,
                            target=target_id,
                            reason="required_credential_absent",
                            detail=", ".join(sorted(tool.requires_credentials)),
                            evidence=tuple(tool_evidence),
                        )
                    )
                    continue
                attempts: list[tuple[CredentialStatus | None, AuthzDecision]] = [
                    (
                        item,
                        evaluator.evaluate(
                            (identity_id, item.assumed_identity or identity_id),
                            resource,
                            action,
                            via_credential=item.id,
                        ),
                    )
                    for item in candidates
                ]
                if not tool.requires_credentials:
                    attempts.append(
                        (
                            None,
                            evaluator.evaluate(
                                (identity_id,), resource, action, via_credential=None
                            ),
                        )
                    )
                for status, decision in attempts:
                    _consider_candidate(
                        analysis_input=analysis_input,
                        environment=environment,
                        ledger=ledger,
                        result=result,
                        index=index,
                        seen=seen,
                        tool=tool,
                        tool_evidence=tool_evidence,
                        action=action,
                        resource=resource,
                        target_id=target_id,
                        state_depth=state_depth,
                        status=status,
                        decision=decision,
                        reach_record=reach.get(target_id),
                        agent_id=agent_id,
                        identity_id=identity_id,
                        agent_environment=agent_environment,
                    )

    _derive_composites(
        ledger, result, index, resources_by_id, seen, reachability, analysis_input, environment
    )
    _collect_uncertainties(result, reachability, analysis_input)
    result.capabilities = sorted(seen.values(), key=lambda item: (item.action.value, item.target))
    return result


def tier_for_environment_name(environment_name: str | None) -> str:
    """Canonical tier for an environment name; unknown names stay UNKNOWN (never assumed safe)."""
    if not environment_name:
        return "unknown"
    known = {"development", "testing", "staging", "production"}
    return environment_name if environment_name in known else "unknown"


def _consider_candidate(
    *,
    analysis_input: AnalysisInput,
    environment: EnvironmentGraph,
    ledger: EvidenceLedger,
    result: ClosureResult,
    index: dict[str, list[str]],
    seen: dict[tuple[str, str, str | None], Capability],
    tool: Tool,
    tool_evidence: list[str],
    action: ActionClass,
    resource: Resource,
    target_id: str,
    state_depth: int,
    status: CredentialStatus | None,
    # Both of these were `object`, which erased the types from every attribute access below --
    # `decision.reachable`, `reach_record.authenticated_for(...)` and friends. They are always a policy
    # decision and a ReachabilityRecord (or None for the latter) at every call site. Annotating them
    # properly is what makes those accesses checkable instead of merely working, and the body below
    # reads the attributes directly rather than through ``getattr`` with a default: a default answers
    # for a misspelled field without saying so, which is the one failure mode the annotation exists to
    # prevent.
    decision: AuthzDecision,
    reach_record: ReachabilityRecord | None,
    agent_id: str,
    identity_id: str,
    agent_environment: str | None,
) -> None:
    """Decide one (tool, action, target, credential) candidate and record what happened."""
    credential_id = status.id if status is not None else None
    allowed = decision.allowed
    reason = decision.reason
    policies = decision.policies
    declared_evidence = sorted(
        {evidence_id for policy_id in policies for evidence_id in index.get(policy_id, [])}
    )

    if not allowed:
        if reason == "deny" and reach_record is not None and reach_record.reachable:
            result.blocked.append(
                BlockedCandidate(
                    tool_id=tool.id,
                    action=action,
                    target=target_id,
                    reason="denied_by_policy",
                    detail=", ".join(policies),
                    evidence=tuple(declared_evidence),
                )
            )
        return

    if reach_record is None or not reach_record.reachable:
        edge_evidence = sorted(
            {
                evidence_id
                for edge_id in (reach_record.edge_ids if reach_record is not None else ())
                for evidence_id in index.get(edge_id, [])
            }
        )
        result.blocked.append(
            BlockedCandidate(
                tool_id=tool.id,
                action=action,
                target=target_id,
                reason="unreachable",
                detail=(reach_record.note if reach_record is not None else "no network evidence"),
                evidence=tuple(sorted(set(declared_evidence) | set(edge_evidence))),
            )
        )
        contradiction_id = make_id(
            "contradiction", "AUTHORITY_UNREACHABLE", resource.id, action.value
        )
        if not any(item.id == contradiction_id for item in result.contradictions):
            result.contradictions.append(
                Contradiction(
                    id=contradiction_id,
                    code="AUTHORITY_UNREACHABLE",
                    subject=resource.id,
                    message=(
                        f"{action.value} on {resource.name} is declared by policy but not reachable: "
                        "the authority exists, the effective capability does not."
                    ),
                    sides={"declared": declared_evidence, "effective": edge_evidence},
                    evidence=sorted(set(declared_evidence) | set(edge_evidence)),
                    severity_impact="capability_removed",
                )
            )
        return

    if status is not None:
        authenticated = reach_record.authenticated_for((status.id,))
    else:
        named = set(reach_record.authenticated_via)
        usable_ids = {item.id for item in result.credential_statuses if item.usable}
        if named:
            authenticated = True if usable_ids & named else None
        else:
            authenticated = None if reach_record.unknown_hops else True
    if authenticated is False:
        result.blocked.append(
            BlockedCandidate(
                tool_id=tool.id,
                action=action,
                target=target_id,
                reason="authentication_failed",
                detail=f"credential {credential_id} is not accepted on the path",
                evidence=tuple(declared_evidence),
            )
        )
        return

    preconditions, precondition_uncertainties = evaluate_preconditions(
        tool, status, result.discovered, target_id
    )
    blockers = applicable_blockers(analysis_input, tool, action, resource.environment)
    kinds = control_kinds(analysis_input, blockers)
    recoverability, mechanisms, recovery_notes = recovery_for(resource)
    cross_environment = bool(
        resource.environment and agent_environment and resource.environment != agent_environment
    )
    verification = (
        VerificationStatus.PROBABLE
        if (authenticated is None or decision.needs_downgrade or state_depth >= 1)
        else VerificationStatus.CONFIRMED
    )
    assessment = assess_severity(
        action,
        resource,
        tier=tier_for_environment_name(resource.environment),
        status=verification,
        recoverability=recoverability,
        blocker_kinds=kinds,
    )

    evidence_ids: set[str] = set(tool_evidence)
    evidence_ids.update(index.get(resource.id, []))
    if status is not None:
        evidence_ids.update(index.get(status.id, []))
    for edge_id in reach_record.edge_ids:
        evidence_ids.update(index.get(edge_id, []))
    evidence_ids.update(declared_evidence)
    proof_id = ledger.inference(
        agent_id,
        "can_execute",
        obj=f"{action.value}:{target_id}",
        supports=tuple(sorted(evidence_ids)),
        note=f"via {tool.id}" + (f" using {credential_id}" if credential_id else ""),
    )
    evidence_ids.add(proof_id)

    uncertainties = list(precondition_uncertainties) + list(recovery_notes)
    if authenticated is None:
        uncertainties.append("network_authentication_unverified")
    if decision.needs_downgrade:
        uncertainties.append("authorization_condition_unverified")
    if status is not None and status.expiry_state == "unknown":
        uncertainties.append("credential_expiry_unknown")
    if cross_environment:
        uncertainties.append("cross_environment_authorization_unverified")
    if state_depth >= 1:
        uncertainties.append("session_state_required")

    path = enriched_path(
        environment,
        agent_id,
        tool,
        credential_id,
        status.assumed_identity if status is not None else None,
        target_id,
    )
    provenance = sorted(
        {
            agent_id,
            tool.id,
            target_id,
            *([credential_id] if credential_id else []),
            *([status.assumed_identity] if status is not None and status.assumed_identity else []),
            *policies,
        }
    )
    capability = Capability(
        id=make_id("capability", action.value, target_id, tool.id, credential_id or identity_id),
        action=action,
        target=target_id,
        environment=resource.environment,
        path=path,
        path_hash=path_hash(path),
        preconditions=preconditions,
        blockers=blockers,
        reachability=ReachabilityView(
            reachable=True,
            authenticated=authenticated,
            authorized=True,
            actionable=verification in {VerificationStatus.CONFIRMED, VerificationStatus.PROBABLE},
        ),
        severity=assessment.severity,
        severity_basis=assessment.basis,
        recoverability=recoverability,
        recovery_mechanisms=mechanisms,
        verification_status=verification,
        confidence=confidence_for(sorted(evidence_ids), verification, ledger),
        evidence=sorted(evidence_ids),
        discovered_by="deterministic",
        state_depth=state_depth,
        uncertainties=sorted(set(uncertainties)),
        cross_environment=cross_environment,
        provenance=provenance,
    )

    key = (action.value, target_id, resource.environment)
    existing = seen.get(key)
    if existing is None or severity_rank(capability.severity) > severity_rank(existing.severity):
        seen[key] = capability
        result.capability_evidence[capability.id] = sorted(evidence_ids)
    else:
        result.capability_evidence.setdefault(existing.id, [])
        result.capability_evidence[existing.id] = sorted(
            set(result.capability_evidence.get(existing.id, [])) | evidence_ids
        )

    if cross_environment:
        contradiction_id = make_id(
            "contradiction", "ENVIRONMENT_BOUNDARY_VIOLATION", resource.id, action.value
        )
        if not any(item.id == contradiction_id for item in result.contradictions):
            result.contradictions.append(
                Contradiction(
                    id=contradiction_id,
                    code="ENVIRONMENT_BOUNDARY_VIOLATION",
                    subject=resource.id,
                    message=(
                        f"The agent is declared for {agent_environment} but holds {action.value} "
                        f"on {resource.name} in {resource.environment}."
                    ),
                    sides={
                        "declared": [index.get(agent_id, ["?"])[0]],
                        "effective": sorted(evidence_ids)[:3],
                    },
                    evidence=sorted(evidence_ids),
                    severity_impact="declared_intent_violated",
                )
            )


def _derive_composites(
    ledger: EvidenceLedger,
    result: ClosureResult,
    index: dict[str, list[str]],
    resources_by_id: dict[str, Resource],
    seen: dict[tuple[str, str, str | None], Capability],
    reachability: ReachabilityAnalyzer,
    analysis_input: AnalysisInput,
    environment: EnvironmentGraph,
) -> None:
    """Derive the composite actions EXFILTRATE and DESTROY from primitives plus controls.

    ``EXFILTRATE`` needs a sensitive read, a route out of the boundary, and no egress inspection.
    ``DESTROY`` needs a delete on a target whose recovery mechanisms are absent or themselves
    deletable by this agent. Neither is visible in a single tool definition, which is why they are
    computed rather than declared.
    """
    egress_available = reachability.has_internet_egress()

    def egress_is_inspected(environment_name: str | None) -> bool:
        """Whether an egress-inspection control covers reads from this environment.

        The scope is the whole point. Asking this question globally -- "does the input contain any DLP
        control at all" -- made a control the corpus scopes to production read as "egress is inspected
        everywhere", which is the opposite of what a scoped control means: it suppressed the
        exfiltration composite in every *other* environment. ``blocker_applies`` applies the
        environment and action scope on the same basis as the rest of the closure (the target's
        environment), and a control that names no environment still covers everywhere.
        """
        return any(
            blocker.kind.value == "dlp"
            and blocker_applies(
                blocker.kind.value, ActionClass.EXFILTRATE, environment_name, blocker.environments
            )
            for blocker in analysis_input.blockers
        )

    for capability in sorted(seen.values(), key=lambda item: item.id):
        resource = resources_by_id.get(capability.target)
        if resource is None:
            continue
        # ``capability.path`` is legitimately empty when the graph holds no agent->tool edge, so the
        # tool id is read defensively: the composite is still derived, it just cannot name the tool.
        tool_id = capability.path[2] if len(capability.path) > 2 else "unknown"

        # --- EXFILTRATE ---------------------------------------------------------------
        # A composite is only ever derived from a *sensitive* read plus a route out of the boundary.
        # That data-class test is the whole definition of the composite, so it is asserted first and
        # unconditionally. An earlier version gated the derivation on a weaker condition (merely that
        # the egress hop was not already present in the path), which silently turned every ordinary
        # READ into an exfiltration claim and produced a false positive in the adversarial corpus.
        if capability.action == ActionClass.READ and resource.data_class in SENSITIVE_DATA_CLASSES:
            if not egress_available:
                result.blocked.append(
                    BlockedCandidate(
                        tool_id=tool_id,
                        action=ActionClass.EXFILTRATE,
                        target=capability.target,
                        reason="no_egress_path",
                        detail="no reachable internet egress from the agent",
                        evidence=tuple(capability.evidence),
                    )
                )
                continue
            if egress_is_inspected(resource.environment):
                result.blocked.append(
                    BlockedCandidate(
                        tool_id=tool_id,
                        action=ActionClass.EXFILTRATE,
                        target=capability.target,
                        reason="dlp_egress_blocked",
                        detail=(
                            "egress inspection covers confidential, customer-PII and "
                            "secret-material data"
                        ),
                        evidence=tuple(capability.evidence),
                    )
                )
                continue
            # Appending the egress hop is only honest if the graph really connects the chain to the
            # internet node. The label is read back out of the graph for the same reason as every other
            # hop: a composite is a stronger claim than a primitive, so an invented edge here would be
            # the most damaging kind of fabrication in the report.
            exfil_path = list(capability.path)
            if "node-internet" not in exfil_path:
                egress = _relay_rel(environment, capability.target, "node-internet")
                if egress:
                    exfil_path.extend([egress, "node-internet"])
            evidence_ids = set(capability.evidence)
            evidence_ids.add(
                ledger.inference(
                    # The acting subject is the agent, not ``capability.path[0]``. A capability can
                    # legitimately carry an empty path -- ``enriched_path`` returns ``[]`` when the
                    # graph holds no agent->tool edge, which its own docstring documents -- and
                    # indexing that crashed the composite pass for an input the module says is
                    # possible. The agent id is also what ``path[0]`` meant here: ``enriched_path``
                    # always begins with it.
                    analysis_input.agent.id,
                    "can_exfiltrate",
                    obj=capability.target,
                    supports=tuple(sorted(evidence_ids)),
                    note="sensitive read + egress + no egress inspection",
                )
            )
            assessment = assess_severity(
                ActionClass.EXFILTRATE,
                resource,
                tier=tier_for_environment_name(resource.environment),
                status=weakest_status(capability.verification_status, VerificationStatus.PROBABLE),
                recoverability=capability.recoverability,
            )
            exfil_composite = capability.model_copy(
                update={
                    "id": make_id("capability", ActionClass.EXFILTRATE.value, capability.target),
                    "action": ActionClass.EXFILTRATE,
                    "path": exfil_path,
                    "path_hash": path_hash(exfil_path),
                    "severity": assessment.severity,
                    "severity_basis": assessment.basis,
                    "evidence": sorted(evidence_ids),
                    "uncertainties": sorted(
                        {*capability.uncertainties, "derived_composite_action"}
                    ),
                    "derived_from": [capability.id],
                }
            )
            _keep_strongest(seen, result, exfil_composite, evidence_ids, resources_by_id)
            continue

        # --- DESTROY ------------------------------------------------------------------
        if capability.action != ActionClass.DELETE:
            continue

        backups = sorted(
            item.id for item in resources_by_id.values() if capability.target in item.backs_up
        )
        if not backups:
            # Irreversibility is only asserted when the resource is known to have no recovery
            # mechanism. Silence is not evidence of safety, and it is not evidence of catastrophe.
            if resource.recovery is None or bool(resource.recovery.mechanisms):
                continue
            if resource.recovery.recoverability == Recoverability.UNKNOWN:
                continue
        else:
            deletable = [
                backup
                for backup in backups
                if (ActionClass.DELETE.value, backup, resources_by_id[backup].environment) in seen
            ]
            if len(deletable) != len(backups):
                continue

        evidence_ids = set(capability.evidence)
        for backup in backups:
            evidence_ids.update(index.get(backup, []))
        evidence_ids.add(
            ledger.inference(
                # The agent, not ``capability.path[0]``: an empty path is a legal capability state
                # here, so the subject cannot be read out of the path. See the exfiltration composite
                # above for the full reasoning.
                analysis_input.agent.id,
                "can_destroy",
                obj=capability.target,
                supports=tuple(sorted(evidence_ids)),
                note="delete plus loss of the declared recovery mechanism",
            )
        )
        assessment = assess_severity(
            ActionClass.DESTROY,
            resource,
            tier=tier_for_environment_name(resource.environment),
            status=weakest_status(capability.verification_status, VerificationStatus.PROBABLE),
            recoverability=Recoverability.POTENTIALLY_IRREVERSIBLE,
        )
        # The composite's path must stay falsifiable hop by hop like every other path. The original code
        # appended ``target DEPENDS_ON backup``, but the graph records the backup relation as
        # ``backup BACKS_UP target`` (see app/graph/builder.py) -- so that hop named a relationship the
        # graph does not carry and pointed the wrong way, an invented edge in the one place the report
        # asserts irreversible impact.
        #
        # A backup cannot simply be spliced in either: the chain already terminates on the target, so any
        # hop naming the target again renders as a self-loop, and the only genuine edges run *backwards*
        # from the target. The backup entities therefore stay out of the path and remain in
        # ``derived_from``, which is where the relationship is already recorded and where a reader can
        # see it without the chain pretending the target backs itself up. The irreversibility claim
        # itself is unchanged and still rests on the evidence ledger, not on this path.
        destroy_path = list(capability.path)
        composite = capability.model_copy(
            update={
                "id": make_id("capability", ActionClass.DESTROY.value, capability.target),
                "action": ActionClass.DESTROY,
                "path": destroy_path,
                "path_hash": path_hash(destroy_path),
                "severity": assessment.severity,
                "severity_basis": assessment.basis,
                "recoverability": Recoverability.POTENTIALLY_IRREVERSIBLE,
                "recovery_mechanisms": [],
                "evidence": sorted(evidence_ids),
                "uncertainties": sorted({*capability.uncertainties, "derived_composite_action"}),
                "derived_from": [capability.id, *backups],
            }
        )
        _keep_strongest(seen, result, composite, evidence_ids, resources_by_id)


def _keep_strongest(
    seen: dict[tuple[str, str, str | None], Capability],
    result: ClosureResult,
    capability: Capability,
    evidence_ids: set[str],
    resources_by_id: dict[str, Resource],
) -> None:
    """Store a derived capability, replacing an existing one only when strictly stronger."""
    environment = (
        resources_by_id[capability.target].environment
        if capability.target in resources_by_id
        else capability.environment
    )
    key = (capability.action.value, capability.target, environment)
    existing = seen.get(key)
    if existing is None or severity_rank(capability.severity) > severity_rank(existing.severity):
        seen[key] = capability
        result.capability_evidence[capability.id] = sorted(evidence_ids)


def _collect_uncertainties(
    result: ClosureResult,
    reachability: ReachabilityAnalyzer,
    analysis_input: AnalysisInput,
) -> None:
    """Global uncertainties that are not attached to a single capability."""
    unknown_hops = sorted(
        target
        for target, record in reachability.records().items()
        if record.reachable and record.unknown_hops
    )
    if unknown_hops:
        result.uncertainties.append(
            Uncertainty(
                id=make_id("uncertainty", "network_authentication_partially_unknown"),
                code="network_authentication_partially_unknown",
                message=(
                    "Some reachable paths do not declare whether authentication is enforced: "
                    + ", ".join(unknown_hops[:5])
                ),
                affects=unknown_hops,
            )
        )
    if result.caps_hit:
        result.uncertainties.append(
            Uncertainty(
                id=make_id("uncertainty", "analysis_truncated", tuple(result.caps_hit)),
                code="analysis_truncated",
                message="The analysis stopped at a configured limit: " + ", ".join(result.caps_hit),
                affects=[],
            )
        )
    if not analysis_input.permissions:
        result.uncertainties.append(
            Uncertainty(
                id=make_id("uncertainty", "insufficient_input", "permissions"),
                code="insufficient_input",
                message=(
                    "No permissions were supplied, so every action is treated as not authorized "
                    "rather than silently assumed allowed."
                ),
                affects=[],
            )
        )
