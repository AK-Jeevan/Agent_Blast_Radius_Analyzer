"""Agentic plane: LLM-assisted reasoning over the deterministic results.

Import direction matters: :mod:`app.agents` may import :mod:`app.analyzers`, never the reverse
(enforced by ``tests/unit/test_architecture.py``). Everything here *proposes*; the deterministic
verifier decides.
"""

from __future__ import annotations

from app.agents.client import (
    LLMClient,
    LLMResponse,
    NvidiaClient,
    ScriptedLLM,
    UsageLedger,
    build_client,
)
from app.agents.pipeline import AgenticAnalyzer, AgenticResult, merge_agentic
from app.agents.verifier import ClaimVerifier, VerificationOutcome

__all__ = [
    "AgenticAnalyzer",
    "AgenticResult",
    "ClaimVerifier",
    "LLMClient",
    "LLMResponse",
    "NvidiaClient",
    "ScriptedLLM",
    "UsageLedger",
    "VerificationOutcome",
    "build_client",
    "merge_agentic",
]
