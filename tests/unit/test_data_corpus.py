"""Corpus integrity tests: schemas, referential integrity, and the no-secrets invariant."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.config import DATA_DIR
from app.security.masking import detect_secret_patterns
from app.services.loader import DataRegistry, load_registry

pytestmark = pytest.mark.unit

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def registry() -> DataRegistry:
    return load_registry()


def test_registry_loads_expected_entities(registry: DataRegistry) -> None:
    counts = registry.counts()
    assert counts["environments"] == 4
    assert counts["identities"] == 7
    assert counts["agents"] == 5
    assert counts["tools"] == 16
    assert counts["credentials"] == 7
    assert counts["resources"] == 17
    assert counts["permissions"] == 13
    assert counts["network"] >= 25
    assert counts["blockers"] == 6


def test_every_tool_action_has_evidence(registry: DataRegistry) -> None:
    for tool in registry.tools.values():
        declared = {action.value for action in tool.actions}
        evidenced = {item.action.value for item in tool.action_evidence}
        assert declared <= evidenced, f"{tool.id}: actions without evidence: {declared - evidenced}"


def test_permission_principals_and_resources_resolve(registry: DataRegistry) -> None:
    for permission in registry.permissions.values():
        assert permission.principal in registry.identities, permission.id
        for resource in permission.resources:
            if "*" in resource:
                continue
            assert resource in registry.resources, f"{permission.id}: {resource}"


def test_network_endpoints_resolve_or_are_external_nodes(registry: DataRegistry) -> None:
    known = set(registry.resources) | set(registry.identities) | set(registry.environments)
    for edge in registry.network.values():
        for endpoint in (edge.from_id, edge.target):
            assert endpoint in known or endpoint.startswith("node-"), f"{edge.id}: {endpoint}"


def test_agent_tool_and_credential_references_resolve(registry: DataRegistry) -> None:
    for agent in registry.agents.values():
        assert agent.identity in registry.identities, agent.id
        for tool_id in agent.tools:
            assert tool_id in registry.tools, f"{agent.id}: {tool_id}"
        for credential_id in agent.credentials_present:
            assert credential_id in registry.credentials, f"{agent.id}: {credential_id}"
        if agent.instructions:
            assert agent.instructions in registry.instructions, agent.id


def test_tool_credential_references_resolve(registry: DataRegistry) -> None:
    for tool in registry.tools.values():
        for credential_id in tool.requires_credentials:
            assert credential_id in registry.credentials, f"{tool.id}: {credential_id}"
        for blocker_id in tool.blockers:
            assert blocker_id in registry.blockers, f"{tool.id}: {blocker_id}"
        for resource_id in tool.discovery_capability:
            assert resource_id in registry.resources, f"{tool.id}: {resource_id}"


def test_credential_assumed_identity_resolves(registry: DataRegistry) -> None:
    for credential in registry.credentials.values():
        if credential.assumed_identity:
            assert credential.assumed_identity in registry.identities, credential.id


def test_no_secret_values_in_the_corpus() -> None:
    """No file in data/ may contain secret-looking material.

    Credential fragments carry ``secret_ref`` locators (``env:CI_DEPLOY_TOKEN``) and never values.
    This test is the CI gate that makes that promise real.
    """
    findings: list[str] = []
    for path in sorted((PROJECT_ROOT / "data").rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".yaml", ".yml"}:
            continue
        text = path.read_text(encoding="utf-8")
        for name in detect_secret_patterns(text):
            findings.append(f"{path.relative_to(PROJECT_ROOT)}: {name}")
    # `env:NAME` locators are not secrets; the pattern scan must not fire on them.
    assert not findings, "secret-like material found in data corpus: " + "; ".join(findings)


def test_credential_fragments_have_no_value_field() -> None:
    payloads: list[dict[str, Any]] = []
    for path in (DATA_DIR / "credentials").glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        payloads.extend(data["credentials"])
    assert payloads, "no credentials loaded"
    for item in payloads:
        assert "value" not in item and "secret_value" not in item
        assert item.get("secret_ref", "").startswith(("env:", "secretref:"))


def test_untrusted_sources_are_marked_untrusted(registry: DataRegistry) -> None:
    """Text that could be attacker-controlled must be labelled untrusted."""
    must_be_untrusted = [
        "tool-helpful-sync",
        "tool-mcp-deploy",
        "tool-query-cloud",
        "tool-write-db",
        "tool-http-request",
    ]
    for tool_id in must_be_untrusted:
        source = registry.tools[tool_id].source
        assert source.trusted is False, f"{tool_id} should carry an untrusted source"
        assert source.untrusted is True
