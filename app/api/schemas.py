"""Request/response models for the HTTP API (master prompt §29)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.analysis import AnalysisInput
from app.schemas.common import RunMode


class AnalyzeRequest(BaseModel):
    """Analyse either a named scenario from the corpus, or an inline environment."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str | None = Field(
        default=None, description="Load this scenario from data/scenarios/ instead of `input`"
    )
    input: AnalysisInput | None = Field(
        default=None,
        description="An explicit agent environment (identity, tools, credentials, ...)",
    )
    run_mode: RunMode = Field(
        default=RunMode.A_DETERMINISTIC,
        description="A_deterministic | B_interpret | C_agentic | D_full",
    )
    with_counterfactuals: bool = False
    persist: bool = False
    prefer_real_llm: bool | None = Field(
        default=None,
        description=(
            "Override LLM_PREFER_REAL for this request. False pins the deterministic scripted "
            "stand-in (reproducible, offline, free); null uses the server default."
        ),
    )


class AnalyzeResponse(BaseModel):
    """The compact result of an analysis, as returned by POST /analyze."""

    model_config = ConfigDict(extra="allow")

    analysis_id: str
    status: str
    run_mode: RunMode
    risk_summary: dict[str, Any]
    capabilities: list[dict[str, Any]]
    blast_radius: dict[str, Any]
    evidence: list[dict[str, Any]]
    uncertainties: list[dict[str, Any]]
    contradictions: list[dict[str, Any]]
    agent_rejected_claims: list[dict[str, Any]] = Field(default_factory=list)
    counterfactuals: list[dict[str, Any]] = Field(default_factory=list)
    injection_attempts: list[dict[str, Any]] = Field(default_factory=list)
    baseline_comparison: dict[str, Any] = Field(default_factory=dict)
    layers: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    scenario_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: str
    version: str
    llm: dict[str, Any]
    data_corpus: dict[str, int]
    runs_stored: int


class MetricsResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    analyses_total: int
    analyses_by_mode: dict[str, int]
    analyses_failed: int
    capabilities_reported: int
    agentic_claims_accepted: int
    agentic_claims_rejected: int
    llm_calls: int
    total_latency_ms: int
    mean_latency_ms: float
    runs_stored: int
