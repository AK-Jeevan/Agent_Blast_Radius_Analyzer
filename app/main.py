"""FastAPI application factory (Phase 12).

    uvicorn app.main:app --reload

The API is read-only with respect to the analyzed environment: it parses inputs, runs the analyzer,
and returns results. It never executes anything it analyses.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app import __version__
from app.api.routes import router
from app.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="Agent Blast-Radius Analyzer",
        version=__version__,
        summary=(
            "Compute the effective blast radius of an AI agent: what it can actually affect, "
            "how it got that capability, and what would reduce it."
        ),
        description=(
            "Deterministic analysis of identity, tools, credentials, permissions, network, and "
            "resources; optional agentic reasoning whose every claim is verified deterministically. "
            "Read-only: the analyzer never modifies the environment it analyses."
        ),
    )
    application.include_router(router, prefix="")

    @application.get("/", include_in_schema=False)
    def index() -> JSONResponse:
        return JSONResponse(
            {
                "service": "agent-blast-radius-analyzer",
                "version": __version__,
                "endpoints": [
                    "POST /analyze",
                    "GET /analysis/{analysis_id}",
                    "GET /analysis/{analysis_id}/report",
                    "GET /analysis/{analysis_id}/graph",
                    "GET /scenarios",
                    "GET /health",
                    "GET /metrics",
                ],
                "docs": "/docs",
                "run_mode_default": settings.default_run_mode,
            }
        )

    return application


app = create_app()
