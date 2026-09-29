"""In-process run store: recent analyses, with optional JSON persistence to disk.

The MVP keeps runs in memory (bounded) and optionally writes each report to
``artifacts/runs/<analysis_id>.json`` so a demo survives a restart. Secrets never reach this store:
a report contains no credential values by construction, and the store re-checks before writing.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.schemas.analysis import AnalysisReport
from app.security.masking import detect_secret_patterns, redact_mapping

MAX_RUNS = 100


@dataclass
class RunStore:
    """Bounded, deterministic-keyed store of completed analyses."""

    max_runs: int = MAX_RUNS
    persist: bool = False
    directory: Path | None = None
    _runs: OrderedDict[str, AnalysisReport] = field(default_factory=OrderedDict, init=False)
    _graphs: dict[str, dict[str, Any]] = field(default_factory=dict, init=False)

    def add(self, report: AnalysisReport) -> None:
        self._runs[report.analysis_id] = report
        while len(self._runs) > self.max_runs:
            dropped, _ = self._runs.popitem(last=False)
            self._graphs.pop(dropped, None)
        if self.persist and self.directory is not None:
            self._write(report)

    def add_graph(self, analysis_id: str, graph: dict[str, Any]) -> None:
        """Store the environment graph captured at analysis time (for the UI graph view)."""
        self._graphs[analysis_id] = graph

    def graph(self, analysis_id: str) -> dict[str, Any] | None:
        return self._graphs.get(analysis_id)

    def get(self, analysis_id: str) -> AnalysisReport | None:
        return self._runs.get(analysis_id)

    def list_ids(self) -> list[str]:
        return list(reversed(self._runs))

    def __len__(self) -> int:
        return len(self._runs)

    # --- persistence --------------------------------------------------------------------
    def _write(self, report: AnalysisReport) -> None:
        # Narrows the Optional for the type checker and asserts the caller honoured the contract.
        # Asserts are this project's documented invariant mechanism (pyproject.toml ignores S101 for
        # ruff); bandit does not read ruff's noqa comments, so B101 needs a marker of its own.
        assert self.directory is not None  # nosec B101
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = redact_mapping(report.model_dump(mode="json", exclude_none=True))
        text = json.dumps(payload, indent=2, default=str)
        # Belt and braces: refuse to persist anything that still smells like a secret.
        if detect_secret_patterns(text):
            return
        (self.directory / f"{report.analysis_id}.json").write_text(text, encoding="utf-8")

    def summary(self, report: AnalysisReport) -> dict[str, Any]:
        """Compact summary used by ``GET /analysis/{id}`` and the UI header."""
        return {
            "analysis_id": report.analysis_id,
            "agent": report.agent.id,
            "run_mode": report.run_mode.value,
            "status": report.status,
            "termination_reason": report.termination_reason,
            "risk_summary": report.risk_summary.model_dump(mode="json"),
            "layer_summary": {
                "declared": report.layers.declared_authority.model_dump(mode="json"),
                "reachable": report.layers.reachable_authority.model_dump(mode="json"),
                "effective": report.layers.effective_capability.model_dump(mode="json"),
                "delta_notes": report.layers.delta_notes,
            },
            "counts": {
                "capabilities": len(report.capabilities),
                "findings": len(report.findings),
                "contradictions": len(report.contradictions),
                "uncertainties": len(report.uncertainties),
                "injection_attempts": len(report.injection_attempts),
                "rejected_claims": len(report.agent_rejected_claims),
                "counterfactuals": len(report.counterfactuals),
                "evidence": len(report.evidence),
            },
            "metrics": report.metrics.model_dump(mode="json"),
            "baseline_comparison": report.baseline_comparison.model_dump(mode="json"),
        }
