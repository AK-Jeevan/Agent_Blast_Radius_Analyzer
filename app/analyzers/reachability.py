"""Reachability: four independent truth values, never collapsed into one boolean.

For every resource the analyzer records:

``reachable``     -- does a network path exist over edges marked reachable?
``authenticated`` -- is a usable credential accepted on that path?
``authorized``    -- does policy permit the action (supplied by the authz evaluator)?
``actionable``    -- reachable AND authenticated AND authorized AND tool-expressible.

``None`` means UNKNOWN, which is different from ``False``: an unknown hop caps the resulting
capability at ``probable`` and is reported as an uncertainty rather than treated as a denial.
"""

from __future__ import annotations

import itertools
from collections import deque
from dataclasses import dataclass, field

from app.graph.builder import EnvironmentGraph
from app.schemas.common import NetworkEgress, Relationship


@dataclass(frozen=True)
class ReachabilityRecord:
    """Reachability facts for one target node, with the path that produced them."""

    target: str
    reachable: bool
    path: tuple[str, ...] = ()
    egress: str | None = None
    edge_ids: tuple[str, ...] = ()
    authenticated_via: tuple[str, ...] = ()
    unknown_hops: tuple[str, ...] = ()
    denied_edges: tuple[str, ...] = ()
    note: str = ""

    def authenticated_for(self, credential_ids: tuple[str, ...]) -> bool | None:
        """Whether one of these credentials is accepted on this path."""
        if not self.reachable:
            return None
        named = set(self.authenticated_via)
        if named & set(credential_ids):
            return True
        if named:
            # A different credential is named on this path, so this one is not proven.
            return None
        if self.unknown_hops:
            return None
        return True

    @property
    def has_denied_route(self) -> bool:
        return bool(self.denied_edges)


@dataclass
class ReachabilityAnalyzer:
    """Computes reachability from the agent's identity through network edges."""

    environment: EnvironmentGraph
    _records: dict[str, ReachabilityRecord] = field(default_factory=dict, init=False)

    def _roots(self) -> list[str]:
        roots = [self.environment.analysis_input.agent.id]
        if self.environment.analysis_input.identity is not None:
            roots.append(self.environment.analysis_input.identity.id)
        return roots

    def compute(self) -> dict[str, ReachabilityRecord]:
        """Breadth-first reachability from the agent, plus explicit-denial bookkeeping."""
        records = self._records
        graph = self.environment.graph
        denied: dict[str, list[str]] = {}

        for _src, dst, data in self.environment.edges_with_rel(Relationship.CONNECTS_TO):
            if data.get("reachable") is False:
                denied.setdefault(dst, []).append(str(data.get("edge_id")))

        queue: deque[tuple[str, tuple[str, ...], tuple[str, ...]]] = deque()
        seen_first: dict[str, tuple[str, ...]] = {}
        for root in self._roots():
            queue.append((root, (root,), ()))
            seen_first.setdefault(root, (root,))

        while queue:
            node, path, edge_ids = queue.popleft()
            for _src, dst, key, data in graph.out_edges(node, keys=True, data=True):
                if data.get("rel") != Relationship.CONNECTS_TO.value:
                    continue
                if data.get("reachable") is False or dst in path:
                    continue
                new_path = (*path, dst)
                if dst not in seen_first:
                    seen_first[dst] = new_path
                    queue.append((dst, new_path, (*edge_ids, str(data.get("edge_id") or key))))

        all_targets = {
            *self.environment.nodes_of_kind("resource"),
            *self.environment.nodes_of_kind("identity"),
            *denied,
        }
        for target in sorted(all_targets):
            # `seen_first` is a lookup that may miss, so the value is a tuple or None. It is named
            # `route` rather than `path` because the breadth-first loop above already binds `path` as a
            # concrete tuple; reusing the name would either shadow it or require re-annotating it as
            # optional, which would be a lie for the rest of that loop.
            route: tuple[str, ...] | None = seen_first.get(target)
            if route is None:
                records[target] = ReachabilityRecord(
                    target=target,
                    reachable=False,
                    denied_edges=tuple(sorted(set(denied.get(target, [])))),
                    note=(
                        "explicit network denial on at least one edge"
                        if denied.get(target)
                        else "no reachable network path from the agent"
                    ),
                )
                continue
            edge_ids, egress, authenticated_via, unknown_hops = self._describe_path(route)
            records[target] = ReachabilityRecord(
                target=target,
                reachable=True,
                path=route,
                egress=egress,
                edge_ids=edge_ids,
                authenticated_via=authenticated_via,
                unknown_hops=unknown_hops,
                denied_edges=tuple(sorted(set(denied.get(target, [])))),
                note=f"path length {len(route) - 1}",
            )
        return records

    def _describe_path(
        self, path: tuple[str, ...]
    ) -> tuple[tuple[str, ...], str | None, tuple[str, ...], tuple[str, ...]]:
        """Summarise the CONNECTS_TO edges along one path."""
        graph = self.environment.graph
        edge_ids: list[str] = []
        egresses: list[str] = []
        authenticated_via: set[str] = set()
        unknown_hops: list[str] = []
        for src, dst in itertools.pairwise(path):
            for _src, _dst, key, data in graph.out_edges(src, keys=True, data=True):
                if _dst != dst or data.get("rel") != Relationship.CONNECTS_TO.value:
                    continue
                edge_ids.append(str(data.get("edge_id") or key))
                if data.get("egress"):
                    egresses.append(str(data["egress"]))
                authenticated_via.update(str(item) for item in data.get("authenticated_via", []))
                if data.get("authenticated") is None and not data.get("authenticated_via"):
                    unknown_hops.append(str(data.get("edge_id") or key))
        # No egress edge on the path means "none declared", which is UNKNOWN rather than "internal";
        # the report treats the two differently, so the distinction must survive.
        egress: str | None
        if NetworkEgress.INTERNET.value in egresses:
            egress = NetworkEgress.INTERNET.value
        else:
            egress = egresses[0] if egresses else None
        return (
            tuple(edge_ids),
            egress,
            tuple(sorted(authenticated_via)),
            tuple(sorted(unknown_hops)),
        )

    def records(self) -> dict[str, ReachabilityRecord]:
        if not self._records:
            self.compute()
        return self._records

    def record(self, target: str) -> ReachabilityRecord | None:
        return self.records().get(target)

    def reachable_targets(self) -> list[str]:
        return sorted(target for target, record in self.records().items() if record.reachable)

    def has_internet_egress(self) -> bool:
        """Whether the agent can reach an internet egress node."""
        return any(
            record.reachable and record.egress == NetworkEgress.INTERNET.value
            for record in self.records().values()
        )

    def denials(self) -> dict[str, tuple[str, ...]]:
        """Targets that have at least one explicitly denied network edge."""
        return {
            target: record.denied_edges
            for target, record in self.records().items()
            if record.has_denied_route
        }
