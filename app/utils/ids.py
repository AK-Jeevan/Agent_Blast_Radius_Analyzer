"""Deterministic id generation, canonical hashing, and stable ordering helpers.

The analyzer promises byte-reproducible deterministic output for identical input, so every id is
derived from content (never from randomness), and every collection that participates in closure
math is sorted by a canonical key before hashing or comparison.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Sequence
from typing import Any, TypeVar

T = TypeVar("T")

#: Prefix conventions (docs/DATA_MODEL.md §0).
ID_PREFIXES: dict[str, str] = {
    "agent": "agent",
    "identity": "ident",
    "tool": "tool",
    "credential": "cred",
    "resource": "res",
    "permission": "pol",
    "network": "net",
    "blocker": "blk",
    "environment": "env",
    "instruction": "instr",
    "evidence": "ev",
    "capability": "cap",
    "finding": "f",
    "contradiction": "ctr",
    "uncertainty": "unc",
    "hypothesis": "hyp",
    "analysis": "an",
    "node": "node",
}


def canonical_json(value: Any) -> str:
    """Serialise to canonical JSON: sorted keys, no incidental whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def content_hash(*parts: Any, length: int = 16) -> str:
    """Stable hex digest over the canonical form of ``parts``."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(canonical_json(part).encode("utf-8"))
        digest.update(b"\x1f")
    return digest.hexdigest()[:length]


def make_id(kind: str, *parts: Any, length: int = 12) -> str:
    """Build a deterministic, type-prefixed identifier, e.g. ``cap-3f9a1c2d4e5f``."""
    prefix = ID_PREFIXES.get(kind, kind)
    return f"{prefix}-{content_hash(*parts, length=length)}"


def numbered_id(kind: str, index: int) -> str:
    """Human-readable sequential id used for evidence/finding ordering, e.g. ``ev-0042``."""
    prefix = ID_PREFIXES.get(kind, kind)
    return f"{prefix}-{index:04d}"


def path_hash(path: Sequence[str]) -> str:
    """Deterministic hash of a capability path (used for dedup and loop detection)."""
    return "sha256:" + content_hash(list(path), length=32)


def stable_sorted(values: Iterable[T], key: Any = None) -> list[T]:
    """Sort deterministically; falls back to the natural order when no key is supplied.

    ``T`` is a bare TypeVar shared with helpers like :func:`dedupe_preserving_order`, which genuinely
    work for any type, so it is deliberately not bound to ``str``. The consequence is that the un-keyed
    ``sorted`` below cannot be proven orderable for an arbitrary ``T``. It is correct in practice --
    every caller passes strings, and passing a key of ``None`` relies on that -- which is why the
    narrowing is documented here rather than left to be rediscovered. A type: ignore is used because
    the alternative is narrowing ``T`` to str, which would be a false claim about the other helpers.
    """
    return sorted(values, key=key) if key is not None else sorted(values)  # type: ignore[type-var]


def dedupe_preserving_order(values: Iterable[T]) -> list[T]:
    """Remove duplicates while keeping first-seen order (order itself is part of the output)."""
    seen: set[T] = set()
    result: list[T] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def chunked(values: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    """Yield consecutive slices; used by the LLM client to bound prompt payload size."""
    for start in range(0, len(values), size):
        yield values[start : start + size]
