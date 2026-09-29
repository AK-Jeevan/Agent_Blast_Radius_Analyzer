"""Agent Blast-Radius Analyzer.

A read-only analyzer that computes the *effective blast radius* of an AI agent from its
declared environment: identity, tools, credentials, permissions, network, resources, blockers.

Architecture (see docs/MVP_ARCHITECTURE.md):

* ``app.analyzers`` -- DETERMINISTIC plane. Facts only. Never imports ``app.agents``.
* ``app.agents``    -- AGENTIC plane. Proposals only, verified by deterministic code.
* ``app.graph``     -- the heterogeneous NetworkX graph and its typed views.
* ``app.schemas``   -- Pydantic models mirroring docs/DATA_MODEL.md.
"""

from __future__ import annotations

__all__ = ["ANALYZER_INVARIANTS", "__version__"]

__version__ = "0.1.0"

#: Non-negotiable product invariants, asserted by tests/security/test_invariants.py.
ANALYZER_INVARIANTS: tuple[str, ...] = (
    "analysis_only",  # never mutates, never executes against an analyzed environment
    "no_secret_values",  # secret values are never modelled, logged, or reported
    "evidence_required",  # HIGH/CRITICAL findings need >=2 FACT evidence items
    "untrusted_text_is_data",  # analyzed text can never occupy an instruction position
    "deterministic_core",  # same input => byte-identical deterministic output
)
