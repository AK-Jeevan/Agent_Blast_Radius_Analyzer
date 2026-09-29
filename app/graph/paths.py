"""Bounded path enumeration over the environment graph.

Every traversal is capped and every cap that fires is reported, so a truncated result is never
mistaken for a complete one (docs/ANALYSIS_ENGINE_SPEC.md §1).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import networkx as nx

from app.graph.builder import EnvironmentGraph
from app.schemas.common import Relationship


@dataclass
class PathSearchResult:
    paths: list[list[str]] = field(default_factory=list)
    truncated: bool = False
    visited_nodes: int = 0


def find_paths_between(
    environment: EnvironmentGraph,
    source: str,
    target: str,
    *,
    relationships: set[Relationship] | None = None,
    max_depth: int = 8,
    max_paths: int = 50,
) -> PathSearchResult:
    """All simple paths from ``source`` to ``target`` up to depth/path caps.

    ``relationships`` restricts which edge types may be traversed; ``None`` means "any".
    """
    graph = environment.graph
    result = PathSearchResult()
    if source not in graph or target not in graph:
        return result

    allowed = {rel.value for rel in relationships} if relationships else None
    stack: list[tuple[str, list[str]]] = [(source, [source])]

    while stack:
        node, path = stack.pop()
        result.visited_nodes += 1
        if node == target and len(path) > 1:
            result.paths.append(path)
            if len(result.paths) >= max_paths:
                result.truncated = True
                break
            continue
        if len(path) - 1 >= max_depth:
            continue
        for _src, dst, data in sorted(graph.out_edges(node, data=True)):
            if allowed is not None and data.get("rel") not in allowed:
                continue
            if dst in path:
                continue
            stack.append((dst, [*path, dst]))

    result.paths.sort(key=lambda p: (len(p), p))
    return result


def enumerate_paths(
    environment: EnvironmentGraph,
    source: str,
    *,
    relationships: set[Relationship] | None = None,
    max_depth: int = 4,
    max_paths: int = 200,
) -> PathSearchResult:
    """Breadth-first bounded enumeration of reachable paths from ``source``."""
    graph = environment.graph
    result = PathSearchResult()
    if source not in graph:
        return result

    allowed = {rel.value for rel in relationships} if relationships else None
    queue: deque[tuple[str, list[str]]] = deque([(source, [source])])

    while queue and len(result.paths) < max_paths:
        node, path = queue.popleft()
        result.visited_nodes += 1
        if len(path) - 1 >= max_depth:
            continue
        for _src, dst, data in sorted(graph.out_edges(node, data=True)):
            if allowed is not None and data.get("rel") not in allowed:
                continue
            if dst in path:
                continue
            new_path = [*path, dst]
            result.paths.append(new_path)
            queue.append((dst, new_path))

    if result.paths and len(result.paths) >= max_paths:
        result.truncated = True
    result.paths.sort(key=lambda p: (len(p), p))
    return result


def shortest_path(
    environment: EnvironmentGraph,
    source: str,
    target: str,
    *,
    relationships: set[Relationship] | None = None,
) -> list[str] | None:
    """Shortest simple path between two nodes, or ``None`` when disconnected."""
    graph = environment.graph
    if source not in graph or target not in graph:
        return None
    allowed = {rel.value for rel in relationships} if relationships else None
    view = nx.subgraph_view(
        graph,
        filter_edge=lambda _u, _v, _k: allowed is None or graph[_u][_v][_k].get("rel") in allowed,
    )
    try:
        return list(nx.shortest_path(view, source, target))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None
