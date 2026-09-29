"""Compatibility and contract tests: the regression net for change.

Two jobs:

1. **Tolerance is verified.** A fragment from a newer producer (unknown field, unknown enum, newer
   ``schema_version``) must still load *and* be reported; strict mode must reject it; and the action
   taxonomy must stay strict, because an unrecognised action may never degrade into something that
   merely looks safe.
2. **The public contract is pinned.** If the taxonomy, relationships, run modes, report keys, or API
   routes change, these tests fail loudly, so no downstream consumer is broken silently.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from app.schemas.analysis import AnalysisInput, AnalysisReport, Capability
from app.schemas.common import (
    ActionClass,
    DataClass,
    EnvironmentTier,
    NetworkEgress,
    Relationship,
    ResourceType,
    RunMode,
    VerificationStatus,
)
from app.schemas.entities import NetworkEdge, Resource, Tool
from app.schemas.tolerance import (
    ENUM_ALIASES,
    SCHEMA_VERSION,
    is_direct_enum_value,
    resolve_enum_value,
)
from app.services.loader import DataError, load_json_fragments, load_registry

pytestmark = pytest.mark.unit


def _write(directory: Path, name: str, payload: dict[str, Any]) -> Path:
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.fixture
def tmp_dir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as name:
        yield Path(name)


def test_unknown_fields_are_ignored_and_reported(tmp_dir: Path) -> None:
    path = _write(
        tmp_dir,
        "resources.json",
        {
            "resources": [
                {"id": "res-x", "name": "x", "type": "bucket", "quantum_entanglement": True}
            ]
        },
    )
    warnings: list[str] = []
    loaded = load_json_fragments(path, Resource, warnings=warnings)
    assert "res-x" in loaded
    assert any("quantum_entanglement" in note for note in warnings)


def test_unknown_enum_degrades_to_unknown_and_is_reported(tmp_dir: Path) -> None:
    path = _write(
        tmp_dir,
        "resources.json",
        {"resources": [{"id": "res-x", "name": "x", "type": "vector_database"}]},
    )
    warnings: list[str] = []
    loaded = load_json_fragments(path, Resource, warnings=warnings)["res-x"]
    assert loaded.type is ResourceType.UNKNOWN
    assert any("vector_database" in note for note in warnings)


def test_enum_aliases_resolve_to_the_intended_member() -> None:
    assert resolve_enum_value(DataClass, "pii") is DataClass.CUSTOMER_PII
    assert resolve_enum_value(EnvironmentTier, "prod") is EnvironmentTier.PRODUCTION
    assert resolve_enum_value(EnvironmentTier, "PRODUCTION") is EnvironmentTier.PRODUCTION
    assert resolve_enum_value(NetworkEgress, "public") is NetworkEgress.INTERNET
    known = {
        "DataClass": DataClass,
        "EnvironmentTier": EnvironmentTier,
        "NetworkEgress": NetworkEgress,
    }
    for (enum_name, alias), target in ENUM_ALIASES.items():
        enum_cls = known.get(enum_name)
        if enum_cls is None:
            continue
        resolved = resolve_enum_value(enum_cls, alias)
        assert resolved is not None, f"alias {enum_name}.{alias} no longer resolves"
        assert str(resolved.value).lower() == target.lower()


def test_direct_values_are_recognised_as_such() -> None:
    assert is_direct_enum_value(DataClass, "confidential") is True
    assert is_direct_enum_value(DataClass, "pii") is False


def test_newer_schema_version_loads_with_a_warning(tmp_dir: Path) -> None:
    path = _write(
        tmp_dir,
        "resources.json",
        {
            "resources": [
                {"id": "res-x", "name": "x", "type": "bucket", "schema_version": SCHEMA_VERSION + 5}
            ]
        },
    )
    warnings: list[str] = []
    load_json_fragments(path, Resource, warnings=warnings)
    assert any("schema_version" in note for note in warnings)


def test_strict_mode_rejects_every_tolerated_drift(tmp_dir: Path) -> None:
    payloads = (
        {"resources": [{"id": "res-x", "name": "x", "type": "bucket", "surprise": 1}]},
        {"resources": [{"id": "res-x", "name": "x", "type": "vector_database"}]},
        {
            "resources": [
                {"id": "res-x", "name": "x", "type": "bucket", "schema_version": SCHEMA_VERSION + 1}
            ]
        },
    )
    for payload in payloads:
        path = _write(tmp_dir, "resources.json", payload)
        with pytest.raises(DataError):
            load_json_fragments(path, Resource, strict=True)


def test_action_taxonomy_stays_strict(tmp_dir: Path) -> None:
    """An unknown action must fail loudly: degrading it would invent or hide authority."""
    path = _write(
        tmp_dir, "tools.json", {"tools": [{"id": "tool-x", "name": "x", "actions": ["TELEPORT"]}]}
    )
    with pytest.raises(DataError) as error:
        load_json_fragments(path, Tool)
    assert "known actions" in str(error.value), "the error should list the actions we do support"


def test_network_edge_accepts_both_alias_and_field_name(tmp_dir: Path) -> None:
    """``from`` (wire) and ``from_id`` (python) must both parse: producers and code disagree."""
    for key in ("from", "from_id"):
        path = _write(
            tmp_dir,
            "network.json",
            {"network": [{"id": "net-x", key: "ident-a", "target": "res-a", "reachable": True}]},
        )
        edge = load_json_fragments(path, NetworkEdge)["net-x"]
        assert edge.from_id == "ident-a"
        assert edge.target == "res-a"


def test_analysis_input_ignores_unknown_fields() -> None:
    """A newer producer can add fields to the analysed environment without breaking analysis."""
    parsed = AnalysisInput.model_validate(
        {
            "agent": {"id": "agent-x", "name": "x", "identity": "ident-a", "future_field": 1},
            "tools": [],
        }
    )
    assert parsed.agent.id == "agent-x"


def test_own_corpus_is_strict_clean() -> None:
    """The shipped corpus must carry no tolerated drift (CI loads it in strict mode)."""
    registry = load_registry(strict=True)
    assert registry.warnings == []
    assert registry.schema_version == SCHEMA_VERSION


# ---------------------------------------------------------------- contracts ----
def test_action_taxonomy_is_pinned() -> None:
    """The vocabulary other systems depend on. Changing it is a breaking change, on purpose."""
    assert ActionClass.known_actions() == (
        "READ",
        "WRITE",
        "CREATE",
        "DELETE",
        "EXECUTE",
        "DEPLOY",
        "ROLLBACK",
        "ROTATE",
        "GRANT",
        "REVOKE",
        "DISCOVER",
        "EXFILTRATE",
        "DESTROY",
    )


def test_relationship_vocabulary_is_pinned() -> None:
    assert {item.value for item in Relationship} >= {
        "USES",
        "REQUIRES",
        "AUTHORIZES",
        "ASSUMES",
        "CONNECTS_TO",
        "DISCOVERS",
        "DEPENDS_ON",
        "BACKS_UP",
        "GATED_BY",
        "IN_ENVIRONMENT",
    }
    assert len(list(Relationship)) == 20, "the edge vocabulary changed; update docs/DATA_MODEL.md"


def test_run_modes_are_pinned() -> None:
    assert [item.value for item in RunMode] == [
        "A_deterministic",
        "B_interpret",
        "C_agentic",
        "D_full",
    ]


def test_verification_status_order_is_pinned() -> None:
    """The ordinal is load-bearing: severity ceilings and aggregation all depend on it."""
    assert [item.value for item in VerificationStatus] == [
        "contradicted",
        "unverified",
        "possible",
        "probable",
        "confirmed",
    ]


def test_report_keys_are_pinned() -> None:
    required = {
        "analysis_id",
        "status",
        "run_mode",
        "termination_reason",
        "agent",
        "layers",
        "risk_summary",
        "capabilities",
        "findings",
        "contradictions",
        "uncertainties",
        "agent_rejected_claims",
        "injection_attempts",
        "counterfactuals",
        "baseline_comparison",
        "trajectory",
        "metrics",
        "evidence",
        "report_text",
    }
    assert required <= set(AnalysisReport.model_fields), "a report field disappeared"


def test_capability_keys_are_pinned() -> None:
    required = {
        "id",
        "action",
        "target",
        "environment",
        "path",
        "reachability",
        "severity",
        "severity_basis",
        "recoverability",
        "verification_status",
        "confidence",
        "evidence",
        "discovered_by",
        "state_depth",
        "provenance",
    }
    assert required <= set(Capability.model_fields)


def test_api_routes_are_pinned() -> None:
    """The public HTTP surface, read from the OpenAPI schema.

    ``app.routes`` is not a reliable source here: FastAPI mounts an included router as a single
    ``_IncludedRouter`` object, so its sub-routes are not visible on the list (they resolve at
    request time). The OpenAPI document is the contract clients actually depend on.
    """
    from app.main import app

    paths = set(app.openapi()["paths"])
    assert {
        "/analyze",
        "/analysis/{analysis_id}",
        "/analysis/{analysis_id}/report",
        "/analysis/{analysis_id}/graph",
        "/scenarios",
        "/capabilities",
        "/health",
        "/metrics",
    } <= paths, f"an API endpoint disappeared; present: {sorted(paths)}"


def test_every_endpoint_answers() -> None:
    """A route that exists in the schema must actually respond (catches mount-level breakage)."""
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/capabilities").status_code == 200
    assert client.get("/scenarios").status_code == 200
    assert client.get("/metrics").status_code == 200
    assert client.get("/analysis/unknown-id").status_code == 404
    response = client.post(
        "/analyze", json={"scenario_id": "scenario-01", "prefer_real_llm": False}
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]
    assert client.get(f"/analysis/{analysis_id}").status_code == 200
    assert client.get(f"/analysis/{analysis_id}/report").status_code == 200
    assert client.get(f"/analysis/{analysis_id}/graph").status_code == 200


def test_capabilities_endpoint_describes_the_build() -> None:
    from fastapi.testclient import TestClient

    from app.main import app

    payload = TestClient(app).get("/capabilities").json()
    assert payload["schema_version"] == SCHEMA_VERSION
    assert set(payload["actions"]) == set(ActionClass.known_actions())
    assert payload["policy"]["input_compatibility"] == "tolerant"
