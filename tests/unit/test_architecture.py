"""Architectural invariants: the rules that make the ablation study possible at all."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP = PROJECT_ROOT / "app"
SCRIPTS = PROJECT_ROOT / "scripts"

pytestmark = pytest.mark.unit


def _python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_deterministic_plane_never_imports_the_agentic_plane() -> None:
    """Rule R6: the dependency arrow points one way, so A/B/C/D are mechanically comparable."""
    offenders: list[str] = []
    for path in _python_files(APP / "analyzers"):
        if any(module.startswith("app.agents") for module in _imported_modules(path)):
            offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert not offenders, f"analyzers must not import app.agents: {offenders}"


def test_analyzers_do_not_import_network_clients() -> None:
    """The deterministic plane never talks to a model or to the network."""
    forbidden = {"openai", "httpx", "requests", "urllib3", "socket"}
    offenders: list[str] = []
    for path in _python_files(APP / "analyzers"):
        offending = forbidden & _imported_modules(path)
        if offending:
            offenders.append(f"{path.relative_to(PROJECT_ROOT)}: {sorted(offending)}")
    assert not offenders, f"deterministic plane reached outside the process: {offenders}"


def test_no_arbitrary_execution_outside_scripts() -> None:
    """Read-only analysis: no subprocess/shell execution anywhere in the application code."""
    offenders: list[str] = []
    for path in _python_files(APP):
        if "subprocess" in _imported_modules(path):
            offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert not offenders, f"app/ must not import subprocess: {offenders}"
    for path in _python_files(APP):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"system", "popen", "exec", "eval"}
            ):
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}: {node.func.attr}()")
    assert not offenders, f"arbitrary execution found: {offenders}"


def test_secret_values_are_never_modelled() -> None:
    """A credential must never gain a value field, even accidentally."""
    from app.schemas.entities import Credential

    fields = set(Credential.model_fields)
    forbidden = {"value", "secret", "secret_value", "api_key", "token", "password"}
    assert not (fields & forbidden), (
        f"credential model exposes secret material: {fields & forbidden}"
    )
    assert "secret_ref" in fields, "credentials must keep a locator (secret_ref)"


def test_every_module_documents_itself() -> None:
    """Each public module has a docstring: this codebase is meant to be read, not just run."""
    missing: list[str] = []
    for path in _python_files(APP):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if not ast.get_docstring(tree):
            missing.append(str(path.relative_to(PROJECT_ROOT)))
    assert not missing, f"modules without a docstring: {missing}"


def test_settings_never_serialise_the_api_key() -> None:
    """The NVIDIA key must not appear in repr() or model_dump() of the settings object."""
    from app.config import Settings

    # Split so the repository's own secret scanners, which grep tracked source text for this exact
    # shape, do not flag a deliberate non-credential fixture. The value the settings object receives
    # is unchanged.
    settings = Settings(nvidia_api_key="nvapi-" + "abcdefghijklmnopqrstuvwxyz012345")
    assert "nvapi-" not in repr(settings)
    assert "nvapi-" not in str(settings.model_dump())
    assert settings.llm_enabled is True
