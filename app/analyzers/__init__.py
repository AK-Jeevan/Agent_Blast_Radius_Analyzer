"""Deterministic analysis plane.

**Import rule (enforced by tests/unit/test_architecture.py):** nothing in this package may import
from :mod:`app.agents`. The dependency arrow points one way only -- the agentic layer consumes
deterministic results, never the reverse. That single rule is what makes the A/B/C/D ablation
mechanically possible.
"""

from __future__ import annotations

from app.analyzers.authz import AuthzDecision, PolicyEvaluator
from app.analyzers.evidence import EvidenceLedger
from app.analyzers.scoring import assess_severity, recovery_for

__all__ = [
    "AuthzDecision",
    "EvidenceLedger",
    "PolicyEvaluator",
    "assess_severity",
    "recovery_for",
]
