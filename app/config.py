"""Application settings, loaded from environment variables (and an optional ``.env``).

No secret value ever lives in this module: ``NVIDIA_API_KEY`` is read from the environment and
is deliberately excluded from ``repr``/serialisation so it cannot leak into logs or reports.

Usage::

    from app.config import get_settings
    settings = get_settings()
    settings.max_agent_steps
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

try:  # pragma: no cover - dotenv is optional at runtime
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover - only when python-dotenv is absent
    pass


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DOCS_DIR = PROJECT_ROOT / "docs"


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:  # pragma: no cover - defensive
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:  # pragma: no cover - defensive
        return default


class Settings(BaseModel):
    """Runtime configuration. Values come from the environment (see ``.env.example``)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    # --- application ---
    app_env: str = "development"
    log_level: str = "INFO"
    log_json: bool = False

    # --- LLM reasoning layer (NVIDIA API, OpenAI-compatible) ---
    # ``exclude=True`` keeps the key out of model_dump() as well as repr(), so a settings dump can
    # never leak it into logs, the API response, or an artifact file.
    nvidia_api_key: str = Field(default="", repr=False, exclude=True)
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"
    # Verified against the NVIDIA model catalog (2026-09): the GLM Flash id is `z-ai/glm-5.3-flash`.
    nvidia_model: str = "z-ai/glm-5.3-flash"
    #: When false, the scripted stand-in is used even if a key exists (tests, offline evaluation).
    llm_prefer_real: bool = True
    #: Per-request timeout for the model. Kept short: a stalled endpoint must degrade fast rather
    #: than make an analysis crawl, and the deterministic plane can always answer without it.
    llm_timeout_seconds: int = 30

    # --- agentic loop budgets ---
    max_agent_steps: int = 12
    max_tool_calls: int = 20
    max_llm_calls: int = 15
    timeout_seconds: int = 90
    default_run_mode: str = "D_full"

    # --- deterministic analysis bounds ---
    max_path_length: int = 8
    max_state_depth: int = 4
    max_paths_per_query: int = 200

    # --- evidence rules ---
    min_facts_for_high_severity: int = 2

    # --- infra ---
    api_host: str = "0.0.0.0"  # noqa: S104 - container default, documented in .env.example
    api_port: int = 8000
    gradio_host: str = "0.0.0.0"  # noqa: S104
    gradio_port: int = 7860
    analyzer_api_url: str = "http://127.0.0.1:8000"
    run_store_dir: str = "artifacts/runs"
    eval_output_dir: str = "artifacts/eval"

    # --- data ---
    data_dir: Path = DATA_DIR

    @field_validator("default_run_mode")
    @classmethod
    def _known_run_mode(cls, value: str) -> str:
        allowed = {"A_deterministic", "B_interpret", "C_agentic", "D_full"}
        if value not in allowed:
            raise ValueError(f"default_run_mode must be one of {sorted(allowed)}")
        return value

    @property
    def llm_enabled(self) -> bool:
        """True when a real NVIDIA API key is configured."""
        return bool(self.nvidia_api_key)

    def run_store_path(self) -> Path:
        path = PROJECT_ROOT / self.run_store_dir
        path.mkdir(parents=True, exist_ok=True)
        return path

    def eval_output_path(self) -> Path:
        path = PROJECT_ROOT / self.eval_output_dir
        path.mkdir(parents=True, exist_ok=True)
        return path


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings(
        app_env=_env_str("APP_ENV", "development"),
        log_level=_env_str("LOG_LEVEL", "INFO"),
        log_json=_env_str("LOG_JSON", "false").lower() == "true",
        nvidia_api_key=_env_str("NVIDIA_API_KEY", ""),
        nvidia_base_url=_env_str("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
        nvidia_model=_env_str("NVIDIA_MODEL", "z-ai/glm-5.3-flash"),
        llm_prefer_real=_env_str("LLM_PREFER_REAL", "true").lower() == "true",
        llm_timeout_seconds=_env_int("LLM_TIMEOUT_SECONDS", 30),
        max_agent_steps=_env_int("MAX_AGENT_STEPS", 12),
        max_tool_calls=_env_int("MAX_TOOL_CALLS", 20),
        max_llm_calls=_env_int("MAX_LLM_CALLS", 15),
        timeout_seconds=_env_int("TIMEOUT_SECONDS", 90),
        default_run_mode=_env_str("DEFAULT_RUN_MODE", "D_full"),
        max_path_length=_env_int("MAX_PATH_LENGTH", 8),
        max_state_depth=_env_int("MAX_STATE_DEPTH", 4),
        max_paths_per_query=_env_int("MAX_PATHS_PER_QUERY", 200),
        min_facts_for_high_severity=_env_int("MIN_FACTS_FOR_HIGH_SEVERITY", 2),
        api_host=_env_str("API_HOST", "0.0.0.0"),  # noqa: S104
        api_port=_env_int("API_PORT", 8000),
        gradio_host=_env_str("GRADIO_HOST", "0.0.0.0"),  # noqa: S104
        gradio_port=_env_int("GRADIO_PORT", 7860),
        analyzer_api_url=_env_str("ANALYZER_API_URL", "http://127.0.0.1:8000"),
        run_store_dir=_env_str("RUN_STORE_DIR", "artifacts/runs"),
        eval_output_dir=_env_str("EVAL_OUTPUT_DIR", "artifacts/eval"),
    )
