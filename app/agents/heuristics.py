"""The scripted client's reasoning: the heuristics a careful analyst would apply by hand.

This module is what :class:`app.agents.client.ScriptedLLM` calls. It reads only the *data* blocks and
the structured environment digest it was given -- never the analyzer's internal state -- and it
produces exactly the JSON shapes a real model is asked for. Keeping it separate makes the substitution
explicit and testable, and it means the pipeline and verifier are exercised identically in both
configurations.
"""

from __future__ import annotations

import json
import re
from fnmatch import fnmatch
from typing import Any

from app.analyzers.taxonomy import keyword_action_hints
from app.schemas.common import ActionClass
from app.utils.ids import canonical_json

#: Policy verbs mapped to the action taxonomy. Only single, unqualified verbs grant an action; this
#: mirrors the evaluator's strictness, so a proposal can never rest on a qualified verb.
_MAPPING_TO_ACTION: dict[str, ActionClass] = {
    "read": ActionClass.READ,
    "write": ActionClass.WRITE,
    "create": ActionClass.CREATE,
    "delete": ActionClass.DELETE,
    "execute": ActionClass.EXECUTE,
    "deploy": ActionClass.DEPLOY,
    "rollback": ActionClass.ROLLBACK,
    "rotate": ActionClass.ROTATE,
    "grant": ActionClass.GRANT,
    "revoke": ActionClass.REVOKE,
}

_UNTRUSTED_BLOCK = re.compile(
    r"<<<UNTRUSTED_DATA.*?>>>\n(.*?)\n<<<END_UNTRUSTED_DATA>>>", re.DOTALL
)


def _parse_environment(user: str) -> dict[str, Any]:
    """Recover the environment digest from the prompt's JSON block.

    Deliberately index-based rather than a regex: ``\\{.*\\}`` with DOTALL over a large prompt
    backtracks catastrophically and would hang the sweep.
    """
    start = user.find("{")
    end = user.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {}
    try:
        # json.loads is typed as returning Any; the declared return is a dict, and the value is only
        # reachable as a mapping here, so it is narrowed rather than leaked.
        parsed = json.loads(user[start : end + 1])
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _untrusted_blocks(system: str) -> list[str]:
    """Extract the *contents* of the untrusted data blocks (as data, never as instructions)."""
    contents: list[str] = []
    for raw in _UNTRUSTED_BLOCK.findall(system):
        try:
            contents.append(str(json.loads(raw)))
        except json.JSONDecodeError:
            continue
    return contents


def _declared_actions(tool: dict[str, Any]) -> set[str]:
    return {str(item) for item in tool.get("declared_actions", [])}


def _matches(pattern: str, resource: dict[str, Any]) -> bool:
    if pattern in {"*", resource["id"]}:
        return True
    if fnmatch(resource["id"], pattern):
        return True
    environment = resource.get("environment")
    return bool(environment) and pattern == environment


def semantics_answer(environment: dict[str, Any], untrusted: list[str]) -> dict[str, Any]:
    """Propose actions a tool under-declares, justified by its own prose."""
    interpretations: list[dict[str, Any]] = []
    for tool in environment.get("tools", []):
        declared = _declared_actions(tool)
        # The tool's own excerpt is the quotable text: anything else would be a quote of the wrong
        # source, which the verifier would (correctly) reject.
        candidates = [tool.get("description_excerpt") or "", tool.get("name") or ""]
        candidates += [text for text in untrusted if tool.get("name") and tool["name"] in text]
        for text in [item for item in candidates if item]:
            hinted = {action.value for action in keyword_action_hints(text)}
            extra = sorted(hinted - declared)
            if "sql" in text.lower() and ActionClass.DELETE.value not in declared:
                extra = sorted({*extra, ActionClass.DELETE.value})
            if extra:
                interpretations.append(
                    {
                        "tool_id": tool["id"],
                        "extra_actions": extra,
                        "span": text[:240],
                        "reason": (
                            "The tool accepts caller-supplied operations, so destructive actions "
                            "follow from its own contract."
                        ),
                    }
                )
                break
    return {"interpretations": interpretations}


def _candidate_credentials(environment: dict[str, Any]) -> list[dict[str, Any]]:
    """Credentials that some tool in scope could reveal (the escalation starting point)."""
    tool_ids = {tool["id"] for tool in environment.get("tools", [])}
    return [
        credential
        for credential in environment.get("credentials", [])
        if set(credential.get("discoverable_via", [])) & tool_ids
    ]


def _generic_caller(environment: dict[str, Any]) -> dict[str, Any] | None:
    """A tool whose free-form target parameter lets it drive any API the network permits."""
    for tool in environment.get("tools", []):
        if tool.get("closed_vocabulary") is False and "EXECUTE" in _declared_actions(tool):
            # Elements come from an untyped environment dict, so each is narrowed before being handed
            # back as dict[str, Any]; returning it untyped would erase the caller's guarantees.
            return tool if isinstance(tool, dict) else None
    return None


def composition_answer(environment: dict[str, Any], untrusted: list[str]) -> dict[str, Any]:
    """Propose chains: reveal a credential, reach a system, then drive an API it does not expose.

    The chain is only a proposal. The verifier re-checks obtainability, reachability, and
    authorization deterministically before anything may be reported.
    """
    chains: list[dict[str, Any]] = []
    caller = _generic_caller(environment)
    if caller is None:
        return {"chains": chains}
    # Quote the *calling* tool's own text, so the verifier can re-check the claim against its source.
    caller_span = (caller.get("description_excerpt") or caller.get("name") or "")[:240]

    resources = {resource["id"]: resource for resource in environment.get("resources", [])}
    permissions = environment.get("permissions", [])

    for credential in _candidate_credentials(environment):
        identity = credential.get("assumed_identity")
        if not identity:
            continue
        granted = [
            permission
            for permission in permissions
            if permission.get("principal") == identity
            and permission.get("effect") == "allow"
            and permission.get("via") in {credential["id"], None}
        ]
        for permission in granted:
            for action in permission.get("actions", []):
                verb = str(action)
                if ":" in verb:
                    # A qualified verb such as read:logs is not a general read; proposing one would
                    # be exactly the phantom-authority bug the evaluator is written to prevent.
                    continue
                mapped = _MAPPING_TO_ACTION.get(verb)
                if mapped is None:
                    continue
                for pattern in permission.get("resources", []):
                    for resource_id, resource in resources.items():
                        if not _matches(pattern, resource):
                            continue
                        chains.append(
                            {
                                "summary": (
                                    f"{caller['id']} can drive {resource_id} as a "
                                    f"{mapped.value} call using the {credential['id']} revealed "
                                    "from the workspace."
                                ),
                                "hops": [
                                    *sorted(credential.get("discoverable_via", [])),
                                    caller["id"],
                                ],
                                "action": mapped.value,
                                "target": resource_id,
                                "credential_id": credential["id"],
                                "state_depth": 1,
                                "rationale": (
                                    "The credential is not granted to the agent, but a workspace "
                                    "tool can read it, and the deployment identity is authorized "
                                    f"for {verb} on this resource."
                                ),
                                "span": caller_span,
                            }
                        )
    return {"chains": chains[:12]}


def stateful_answer(environment: dict[str, Any], untrusted: list[str]) -> dict[str, Any]:
    """Propose capabilities that require a discovery step first.

    The discovery is only proposed when a structured ``discovery_capability`` already names the
    revealed entity; prose can motivate the search but can never create the entity.
    """
    proposals: list[dict[str, Any]] = []
    for tool in environment.get("tools", []):
        for resource_id in tool.get("discovery_capability", []):
            for other in environment.get("tools", []):
                if other["id"] == tool["id"] or other.get("closed_vocabulary", True):
                    continue
                for action in sorted(_declared_actions(other)):
                    proposals.append(
                        {
                            "summary": (
                                f"{other['id']} can act on {resource_id} only after "
                                f"{tool['id']} reveals it."
                            ),
                            "discovery_step": {"tool_id": tool["id"], "reveals": resource_id},
                            "action": action,
                            "target": resource_id,
                            "credential_id": (environment.get("credentials") or [{}])[0].get("id"),
                            "state_depth": 1,
                            "rationale": (
                                "The acting tool addresses discovered endpoints, so the capability "
                                "exists only in state >= 1."
                            ),
                        }
                    )
    return {"stateful": proposals[:12]}


def answer_prompt(*, system: str, user: str, schema_hint: str) -> dict[str, Any]:
    """Dispatch a prompt to the matching heuristic, mirroring what a model is asked to produce."""
    environment = _parse_environment(user)
    untrusted = _untrusted_blocks(system)
    if '"interpretations"' in schema_hint:
        return semantics_answer(environment, untrusted)
    if '"chains"' in schema_hint:
        return composition_answer(environment, untrusted)
    if '"stateful"' in schema_hint:
        return stateful_answer(environment, untrusted)
    return {"error": "unrecognised_task", "digest": canonical_json(environment)[:200]}
