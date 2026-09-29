"""Graph builder: turn a validated :class:`AnalysisInput` into an inspectable graph.

Only *structured facts* become edges. Untrusted prose is attached as node attributes (review
material) and never as a relationship, so nothing a model reads can create a traversable edge.

Node kinds: ``agent``, ``identity``, ``tool``, ``credential``, ``resource``, ``blocker``,
``environment``. Edge attribute ``rel`` holds a :class:`Relationship` value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx

from app.schemas.analysis import AnalysisInput
from app.schemas.common import Relationship, ResourceType
from app.schemas.entities import Resource

KIND = "kind"


@dataclass
class EnvironmentGraph:
    """A built graph plus the convenience queries the analyzers rely on."""

    graph: nx.MultiDiGraph
    analysis_input: AnalysisInput

    # --- node queries -------------------------------------------------------------------
    def nodes_of_kind(self, kind: str) -> list[str]:
        return sorted(node for node, data in self.graph.nodes(data=True) if data.get(KIND) == kind)

    def node_kind(self, node_id: str) -> str | None:
        if node_id not in self.graph:
            return None
        # networkx types node attribute dicts as Any, so the value is narrowed explicitly rather than
        # letting an untyped attribute escape as Any through a `str | None` signature.
        value = self.graph.nodes[node_id].get(KIND)
        return str(value) if value is not None else None

    def resource(self, resource_id: str) -> Resource | None:
        for resource in self.analysis_input.resources:
            if resource.id == resource_id:
                return resource
        return None

    def resource_environment(self, resource_id: str) -> str | None:
        resource = self.resource(resource_id)
        return resource.environment if resource else None

    # --- edge queries -------------------------------------------------------------------
    def edges_with_rel(self, rel: Relationship) -> list[tuple[str, str, dict[str, Any]]]:
        return [
            (src, dst, data)
            for src, dst, _key, data in self.graph.edges(keys=True, data=True)
            if data.get("rel") == rel.value
        ]

    def outgoing(self, node_id: str, rel: Relationship) -> list[str]:
        if node_id not in self.graph:
            return []
        return sorted(
            dst
            for _src, dst, data in self.graph.out_edges(node_id, data=True)
            if data.get("rel") == rel.value
        )

    def incoming(self, node_id: str, rel: Relationship) -> list[str]:
        if node_id not in self.graph:
            return []
        return sorted(
            src
            for src, _dst, data in self.graph.in_edges(node_id, data=True)
            if data.get("rel") == rel.value
        )

    def counts(self) -> dict[str, int]:
        summary: dict[str, int] = {
            kind: len(self.nodes_of_kind(kind))
            for kind in (
                "agent",
                "identity",
                "tool",
                "credential",
                "resource",
                "blocker",
                "environment",
            )
        }
        summary["edges"] = self.graph.number_of_edges()
        return summary

    def to_serialisable(self) -> dict[str, Any]:
        """Graph view for the API/UI graph endpoint."""
        nodes = [
            {
                "id": node,
                "kind": data.get(KIND),
                "label": data.get("label", node),
                "environment": data.get("environment"),
                "trust": data.get("trust", "trusted"),
            }
            for node, data in sorted(self.graph.nodes(data=True))
        ]
        edges = [
            {
                "source": src,
                "target": dst,
                "rel": data.get("rel"),
                "reachable": data.get("reachable"),
                "hypothesis": bool(data.get("hypothesis", False)),
                "evidence": list(data.get("evidence", [])),
            }
            for src, dst, data in sorted(
                (
                    (source, target, data)
                    for source, target, _key, data in self.graph.edges(keys=True, data=True)
                ),
                key=lambda item: (item[0], item[1], str(item[2].get("rel"))),
            )
        ]
        return {"nodes": nodes, "edges": edges, "counts": self.counts()}


def build_graph(analysis_input: AnalysisInput) -> EnvironmentGraph:
    """Build the environment graph from structured facts only."""
    graph = nx.MultiDiGraph()
    input_ = analysis_input

    def add_node(node_id: str, kind: str, **attrs: Any) -> None:
        """Add a node, or *upgrade* an existing placeholder to its real kind.

        Edges can reference an entity before that entity's own block is processed (for example a
        tool's DISCOVERS edge naming a resource). Without the upgrade, the node would stay a generic
        ``node`` and silently drop out of every typed view.
        """
        attributes: dict[str, Any] = {KIND: kind, **attrs}
        attributes.setdefault("label", node_id)
        if node_id in graph:
            existing = graph.nodes[node_id]
            if existing.get(KIND) == "node" and kind != "node":
                existing.update(attributes)
            else:
                for key, value in attributes.items():
                    existing.setdefault(key, value)
            return
        graph.add_node(node_id, **attributes)

    def add_edge(src: str, dst: str, rel: Relationship, **attrs: Any) -> None:
        if src not in graph:
            add_node(src, "node")
        if dst not in graph:
            add_node(dst, "node")
        graph.add_edge(src, dst, rel=rel.value, **attrs)

    def env_node(environment_name: str) -> str:
        """Environment nodes are keyed by *name* so cross-environment links stay visible."""
        node_id = f"environment:{environment_name}"
        add_node(node_id, "environment", label=environment_name, environment=environment_name)
        return node_id

    add_node(
        input_.agent.id,
        "agent",
        label=input_.agent.name,
        trust="trusted" if input_.agent.source.trusted else "untrusted",
    )
    if input_.environment is not None:
        add_node(
            input_.environment.id,
            "environment",
            label=input_.environment.name,
            tier=input_.environment.tier.value,
            environment=input_.environment.name,
        )
    if input_.identity is not None:
        add_node(
            input_.identity.id,
            "identity",
            label=input_.identity.name,
            environment=input_.identity.environment,
        )
        add_edge(
            input_.agent.id,
            input_.identity.id,
            Relationship.HAS_ACCESS_TO,
            note="agent runs as this identity",
        )
        if input_.identity.environment:
            add_edge(
                input_.identity.id,
                env_node(input_.identity.environment),
                Relationship.IN_ENVIRONMENT,
            )

    for tool in input_.tools:
        add_node(
            tool.id,
            "tool",
            label=tool.name,
            trust="trusted" if tool.source.trusted else "untrusted",
            is_mcp=tool.is_mcp,
        )
        add_edge(input_.agent.id, tool.id, Relationship.USES)
        for credential_id in tool.requires_credentials:
            add_edge(tool.id, credential_id, Relationship.REQUIRES)
        for blocker_id in tool.blockers:
            add_edge(tool.id, blocker_id, Relationship.GATED_BY)
        for resource_id in tool.discovery_capability:
            add_edge(
                tool.id,
                resource_id,
                Relationship.DISCOVERS,
                note="tool output can reveal this resource",
            )
        # The resources a tool declares it can act on. Without this edge every tool is a dead end in
        # the graph, so no capability path could ever reach its target and the path would stop at
        # "agent USES tool" -- technically true but useless as evidence, and it would silently hide
        # the tool->target relationship the analysis actually depends on. Declared targets are a
        # *claim* of reachability, so the edge is marked as such: the reachability analyser still has
        # to confirm it.
        for resource_id in tool.targets:
            if resource_id in {resource.id for resource in input_.resources}:
                add_edge(
                    tool.id,
                    resource_id,
                    Relationship.CONNECTS_TO,
                    note="declared tool target; reachability unconfirmed",
                    declared=True,
                )

    for credential in input_.credentials:
        add_node(
            credential.id,
            "credential",
            label=credential.id,
            environment=(credential.scope[0] if credential.scope else None),
        )
        if credential.assumed_identity:
            add_node(credential.assumed_identity, "identity", label=credential.assumed_identity)
            add_edge(credential.id, credential.assumed_identity, Relationship.ASSUMES)
        for tool_id in credential.discoverable_via:
            add_edge(
                tool_id,
                credential.id,
                Relationship.DISCOVERS,
                note="credential can be read through this tool",
            )
        for scope in credential.scope:
            add_edge(credential.id, env_node(scope), Relationship.IN_ENVIRONMENT)

    return _add_sources_and_network(graph, input_, add_node, add_edge, env_node)


def _add_sources_and_network(
    graph: nx.MultiDiGraph,
    input_: AnalysisInput,
    add_node: Any,
    add_edge: Any,
    env_node: Any,
) -> EnvironmentGraph:
    """Add resources, blockers, network edges, and concrete permission edges."""
    for resource in input_.resources:
        add_node(
            resource.id,
            "resource",
            label=resource.name,
            environment=resource.environment,
            resource_type=resource.type.value,
            data_class=resource.data_class.value,
            criticality=resource.criticality,
            trust="trusted" if resource.source.trusted else "untrusted",
        )
        if resource.environment:
            add_edge(resource.id, env_node(resource.environment), Relationship.IN_ENVIRONMENT)
        for dependent in resource.dependents:
            add_edge(resource.id, dependent, Relationship.DEPENDS_ON)
        for target in resource.backs_up:
            add_edge(resource.id, target, Relationship.BACKS_UP)

    for blocker in input_.blockers:
        add_node(blocker.id, "blocker", label=blocker.name, blocker_kind=blocker.kind.value)

    for edge in input_.network:
        add_edge(
            edge.from_id,
            edge.target,
            Relationship.CONNECTS_TO,
            reachable=edge.reachable,
            egress=edge.egress.value,
            authenticated=edge.authenticated,
            authenticated_via=list(edge.authenticated_via),
            protocol=edge.protocol,
            boundary=edge.boundary,
            edge_id=edge.id,
            evidence=[edge.id],
        )

    # Permission edges are materialised only for concrete (non-glob) grants so the visualisation
    # stays readable. Authorization decisions come from the evaluator, never from these edges.
    concrete_resources = {resource.id for resource in input_.resources}
    for permission in input_.permissions:
        for resource_id in permission.resources:
            if resource_id in concrete_resources:
                add_edge(
                    permission.principal,
                    resource_id,
                    Relationship.HAS_ACCESS_TO,
                    effect=permission.effect,
                    actions=list(permission.actions),
                    policy=permission.id,
                    evidence=[permission.id],
                )

    return EnvironmentGraph(graph=graph, analysis_input=input_)


#: Resource types that represent network endpoints rather than data stores.
ENDPOINT_TYPES: frozenset[ResourceType] = frozenset(
    {ResourceType.SERVICE, ResourceType.ENDPOINT, ResourceType.PIPELINE}
)
