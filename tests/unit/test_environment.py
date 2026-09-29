"""Environment and Phase-0 contract checks.

These tests deliberately require no application code: they prove that the `Agent3`
environment, the lint/test toolchain, and the Phase 0 artefacts are all in place and
internally consistent before any analysis code is written.

Run with:
    .\\Agent3\\Scripts\\python.exe -m pytest tests/unit/test_environment.py -q
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCS = PROJECT_ROOT / "docs"

REQUIRED_PACKAGES = (
    "pydantic",
    "networkx",
    "yaml",
    "fastapi",
    "uvicorn",
    "httpx",
    "openai",
    "gradio",
    "structlog",
    "dotenv",
)

# Phase 0 artefacts that later phases build on. Missing/baseline-empty files fail the build.
REQUIRED_DOCS = (
    "PHASE_0_PROBLEM_DEFINITION.md",
    "DATA_MODEL.md",
    "ANALYSIS_ENGINE_SPEC.md",
    "SIMULATED_ENVIRONMENT.md",
    "EVALUATION_PLAN.md",
)

# Core design rules that must stay documented. If one disappears, the corresponding
# guarantee has probably been silently dropped somewhere in the code.
REQUIRED_RULES = {
    "None means UNKNOWN": "UNKNOWN",
    "declared vs reachable vs authorized vs actionable": "actionable",
    "explicit deny wins": "deny",
    "baseline before LLM": "baseline",
}


def test_python_version_supported() -> None:
    """The project targets Python 3.12+; the Agent3 venv currently runs 3.14."""
    assert sys.version_info >= (3, 12), f"unsupported interpreter: {sys.version}"


def test_required_packages_importable() -> None:
    """Every runtime dependency in requirements.txt must import in this environment."""
    missing = []
    for module_name in REQUIRED_PACKAGES:
        try:
            importlib.import_module(module_name)
        except ImportError as exc:  # pragma: no cover - only on a broken env
            missing.append(f"{module_name}: {exc}")
    assert not missing, "missing dependencies: " + "; ".join(missing)


def test_docs_directory_contains_phase_0_artifacts() -> None:
    for name in REQUIRED_DOCS:
        path = DOCS / name
        assert path.is_file(), f"missing Phase 0 document: docs/{name}"
        assert path.stat().st_size > 1_000, f"docs/{name} looks like a stub"


@pytest.mark.parametrize(("label", "needle"), sorted(REQUIRED_RULES.items()))
def test_design_rules_are_documented(label: str, needle: str) -> None:
    """The Phase 0 documents must still state each load-bearing design rule."""
    corpus = "\n".join((DOCS / name).read_text(encoding="utf-8") for name in REQUIRED_DOCS)
    assert needle.lower() in corpus.lower(), f"design rule no longer documented: {label}"


def test_env_example_has_no_secret_values() -> None:
    """`.env.example` may define empty placeholders but must never carry a real value."""
    text = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.split("#", 1)[0].strip()
        if key in {"NVIDIA_API_KEY"}:
            assert value == "", f"{key} must stay empty in the template"
        if re.search(r"(?i)(secret|key|token|passwor)", key):
            assert not re.fullmatch(r"nvapi-[A-Za-z0-9_\-]{8,}", value), (
                f"real-looking secret in {key}"
            )


def test_gitignore_excludes_env_and_venv() -> None:
    text = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in text, ".gitignore must exclude .env"
    assert "Agent3/" in text, ".gitignore must exclude the Agent3 virtual environment"


def test_requirements_pins_the_validated_stack() -> None:
    text = (PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8")
    for expected in ("networkx", "pydantic", "fastapi", "gradio", "openai", "pytest", "ruff"):
        assert expected in text, f"requirements.txt is missing {expected}"
