"""API routes: analyse an agent environment and read the results back.

The API is a thin shell over :mod:`app.services.orchestrator`; all analysis logic lives in the
service layer so the same behaviour is reachable from the CLI, the UI, and the tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import PlainTextResponse

from app import __version__
from app.analyzers.engine import make_analysis_id
from app.api.schemas import AnalyzeRequest
from app.config import DATA_DIR, get_settings
from app.graph.builder import build_graph
from app.schemas.analysis import AnalysisReport, CounterfactualOp
from app.schemas.common import (
    ActionClass,
    DataClass,
    EnvironmentTier,
    Recoverability,
    Relationship,
    ResourceType,
    RunMode,
    Severity,
    VerificationStatus,
)
from app.schemas.scenario import Scenario
from app.schemas.tolerance import SCHEMA_VERSION
from app.services.loader import (
    DataError,
    DataRegistry,
    build_analysis_input,
    load_registry,
    load_scenarios,
)
from app.services.orchestrator import analyse
from app.services.store import RunStore

router = APIRouter()
store = RunStore()


def _counterfactual_operation_kinds() -> list[str]:
    """The Literal values accepted by :class:`CounterfactualOp.kind`, read from the model itself.

    Reading ``model_fields["kind"].annotation.__args__`` inline is how the schema endpoint advertised
    the operations, but the annotation is typed ``Any | None`` on a FieldInfo, so a rename of the
    field -- or a plain ``str`` annotation -- turns the endpoint into a 500 at request time rather
    than a visible failure at import time. Extracting the values defensively keeps ``/schema`` from
    becoming a runtime crash surface: if the introspection ever stops working it reports an empty
    list, which is honest, instead of raising.
    """
    annotation = CounterfactualOp.model_fields["kind"].annotation
    return [str(value) for value in getattr(annotation, "__args__", ()) or ()]


class Corpus:
    """Lazy, cached access to the data corpus.

    A class rather than module-level ``global`` caches: the loaded state belongs to one object, so it
    can be swapped in a test, invalidated after a corpus change, or served together with the
    compatibility warnings the loader recorded.
    """

    def __init__(self, data_dir: Path | None = None, *, strict: bool = False) -> None:
        self.data_dir = data_dir
        self.strict = strict
        self._registry: DataRegistry | None = None
        self._scenarios: list[Scenario] = []

    def scenarios_dir(self) -> Path:
        return (self.data_dir / "scenarios") if self.data_dir else (DATA_DIR / "scenarios")

    def registry(self) -> DataRegistry:
        if self._registry is None:
            self._registry = load_registry(self.data_dir, strict=self.strict)
        return self._registry

    def scenarios(self) -> list[Scenario]:
        if not self._scenarios:
            self._scenarios = load_scenarios(self.scenarios_dir())
        return self._scenarios

    def reset(self) -> None:
        """Drop cached state (used after the corpus changes on disk, and by tests)."""
        self._registry = None
        self._scenarios = []


corpus = Corpus()


def registry() -> DataRegistry:
    """The data corpus, loaded once per process (and shared with the UI)."""
    return corpus.registry()


def scenarios() -> list[Scenario]:
    """The scenario catalogue, loaded once per process."""
    return corpus.scenarios()


#: Lightweight process counters for /metrics (no external metrics dependency in the MVP).
counters: dict[str, Any] = {
    "analyses_total": 0,
    "analyses_failed": 0,
    "analyses_by_mode": {},
    "capabilities_reported": 0,
    "agentic_claims_accepted": 0,
    "agentic_claims_rejected": 0,
    "llm_calls": 0,
    "total_latency_ms": 0,
    "compatibility_warnings": 0,
}


def _resolve_input(request: AnalyzeRequest) -> Any:
    if request.scenario_id:
        match = next(
            (item for item in scenarios() if item.id.startswith(request.scenario_id)), None
        )
        if match is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"unknown scenario: {request.scenario_id}",
            )
        return build_analysis_input(registry(), match, run_mode=request.run_mode)
    if request.input is not None:
        return request.input.model_copy(update={"run_mode": request.run_mode})
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="provide either 'scenario_id' or 'input'",
    )


@router.post("/analyze", response_model=dict)
def create_analysis(request: AnalyzeRequest) -> dict[str, Any]:
    """Analyse an agent environment and return the blast-radius report."""
    try:
        analysis_input = _resolve_input(request)
    except DataError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)
        ) from error

    settings = get_settings()
    if request.prefer_real_llm is not None:
        settings = settings.model_copy(update={"llm_prefer_real": request.prefer_real_llm})
    try:
        outcome = analyse(
            analysis_input,
            run_mode=request.run_mode,
            settings=settings,
            with_counterfactuals=request.with_counterfactuals,
        )
    except Exception as error:  # surfaced to the caller, never swallowed
        counters["analyses_failed"] += 1
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{type(error).__name__}: {error}",
        ) from error

    report = outcome.report
    store.add(report)
    store.add_graph(report.analysis_id, build_graph(analysis_input).to_serialisable())
    _count(report)
    return _payload(report, outcome.notes)


def _payload(report: AnalysisReport, notes: list[str]) -> dict[str, Any]:
    """The response body: capabilities, layers, evidence, and the honesty blocks."""
    return {
        "analysis_id": report.analysis_id,
        "status": report.status,
        "run_mode": report.run_mode,
        "risk_summary": report.risk_summary.model_dump(mode="json"),
        "capabilities": [
            {
                "id": item.id,
                "action": item.action.value,
                "target": item.target,
                "environment": item.environment,
                "severity": item.severity.value,
                "status": item.verification_status.value,
                "confidence": item.confidence,
                "state_depth": item.state_depth,
                "discovered_by": item.discovered_by,
                "path": item.path,
            }
            for item in report.capabilities
        ],
        "blast_radius": {
            "layers": {
                "declared": report.layers.declared_authority.model_dump(mode="json"),
                "reachable": report.layers.reachable_authority.model_dump(mode="json"),
                "effective": report.layers.effective_capability.model_dump(mode="json"),
                "delta_notes": report.layers.delta_notes,
            },
            "findings": [finding.model_dump(mode="json") for finding in report.findings],
            "counterfactuals": [item.model_dump(mode="json") for item in report.counterfactuals],
        },
        "evidence": [item.model_dump(mode="json") for item in report.evidence],
        "uncertainties": [item.model_dump(mode="json") for item in report.uncertainties],
        "contradictions": [item.model_dump(mode="json") for item in report.contradictions],
        "agent_rejected_claims": [
            item.model_dump(mode="json") for item in report.agent_rejected_claims
        ],
        "injection_attempts": [item.model_dump(mode="json") for item in report.injection_attempts],
        "baseline_comparison": report.baseline_comparison.model_dump(mode="json"),
        "metrics": report.metrics.model_dump(mode="json"),
        "scenario_id": report.scenario_id,
        "notes": notes,
    }


def _count(report: AnalysisReport) -> None:
    """Update the process counters served by ``/metrics``."""
    counters["analyses_total"] += 1
    counters["capabilities_reported"] += len(report.capabilities)
    counters["llm_calls"] += report.metrics.llm_calls
    counters["total_latency_ms"] += report.metrics.latency_ms
    counters["agentic_claims_accepted"] += sum(
        1 for item in report.capabilities if item.discovered_by != "deterministic"
    )
    counters["agentic_claims_rejected"] += len(report.agent_rejected_claims)
    by_mode = counters["analyses_by_mode"]
    by_mode[report.run_mode.value] = by_mode.get(report.run_mode.value, 0) + 1


@router.get("/analysis/{analysis_id}")
def read_analysis(analysis_id: str) -> dict[str, Any]:
    """Full stored report, plus a compact summary for dashboards."""
    report = _require(analysis_id)
    return {
        **store.summary(report),
        "report": report.model_dump(mode="json", exclude_none=True),
    }


@router.get("/analysis/{analysis_id}/report", response_class=PlainTextResponse)
def read_report_text(analysis_id: str) -> str:
    """The rendered text report (master prompt §18 layout)."""
    report = _require(analysis_id)
    return report.report_text or "(no rendered report)"


@router.get("/analysis/{analysis_id}/graph")
def read_graph(analysis_id: str) -> dict[str, Any]:
    """Nodes and edges for the graph view (captured during the analysis run)."""
    report = _require(analysis_id)
    captured = store.graph(analysis_id)
    if captured is not None:
        return captured
    return build_graph(_input_for_graph(report)).to_serialisable()


def _input_for_graph(report: AnalysisReport) -> Any:
    """Rebuild enough of the analysed input to re-derive its graph view.

    The stored report keeps the agent, identity, and environment; the graph view therefore shows the
    agent/identity/environment skeleton plus the capability paths that were actually derived.
    """
    from app.schemas.analysis import AnalysisInput

    skeleton = AnalysisInput(
        agent=report.agent,
        environment=report.environment,
        identity=report.identity,
    )
    for capability in report.capabilities:
        for index in range(1, len(capability.path) - 1, 2):
            entity = capability.path[index + 1]
            if entity not in skeleton.entity_ids():
                skeleton = skeleton.model_copy(update={"resources": [*skeleton.resources]})
    return skeleton


def _require(analysis_id: str) -> AnalysisReport:
    report = store.get(analysis_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"unknown analysis: {analysis_id}"
        )
    return report


@router.get("/scenarios")
def list_scenarios() -> list[dict[str, Any]]:
    """Scenario catalogue for the UI and for reproducible inputs."""
    from app.services.loader import scenario_expectation_summary

    return [scenario_expectation_summary(scenario) for scenario in scenarios()]


@router.get("/capabilities")
def analyzer_capabilities() -> dict[str, Any]:
    """What this build understands, so a client can adapt instead of guessing.

    This is the compatibility surface: the action taxonomy, the relationship vocabulary, the run
    modes, the counterfactual operations, the schema revision, and the evidence policy. A caller that
    reads this can tell *before* submitting an analysis whether its data will be understood.
    """
    settings = get_settings()
    return {
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "actions": list(ActionClass.known_actions()),
        "severities": [item.value for item in Severity],
        "verification_statuses": [item.value for item in VerificationStatus],
        "recoverability": [item.value for item in Recoverability],
        "data_classes": [item.value for item in DataClass],
        "resource_types": [item.value for item in ResourceType],
        "environment_tiers": [item.value for item in EnvironmentTier],
        "relationships": [item.value for item in Relationship],
        "run_modes": [mode.value for mode in RunMode],
        "counterfactual_operations": _counterfactual_operation_kinds(),
        "policy": {
            "min_facts_for_high_severity": settings.min_facts_for_high_severity,
            "max_state_depth": settings.max_state_depth,
            "max_path_length": settings.max_path_length,
            "default_run_mode": settings.default_run_mode,
            "input_compatibility": "tolerant",
            "output_compatibility": "strict",
        },
        "llm": {
            "key_configured": settings.llm_enabled,
            "model": settings.nvidia_model,
            "prefer_real": settings.llm_prefer_real,
        },
    }


@router.get("/health")
def health() -> dict[str, Any]:
    """Liveness plus the configuration facts a reviewer needs (never the key itself)."""
    settings = get_settings()
    return {
        "status": "ok",
        "version": __version__,
        "llm": {
            "key_configured": settings.llm_enabled,
            "prefer_real": settings.llm_prefer_real,
            "model": settings.nvidia_model,
            "base_url": settings.nvidia_base_url,
        },
        "data_corpus": registry().counts(),
        "runs_stored": len(store),
    }


@router.get("/metrics")
def metrics() -> dict[str, Any]:
    """Process counters: volume, quality signals, and reasoning cost."""
    total = counters["analyses_total"]
    return {
        **counters,
        "mean_latency_ms": round(counters["total_latency_ms"] / total, 2) if total else 0.0,
        "runs_stored": len(store),
        "run_modes": [mode.value for mode in RunMode],
        "id_scheme": make_analysis_id.__name__,
    }
