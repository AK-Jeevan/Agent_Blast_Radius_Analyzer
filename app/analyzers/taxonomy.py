"""Action taxonomy: verbs, severity tables, and deterministic keyword hints.

The tables here are the *only* place severity is decided (docs/ANALYSIS_ENGINE_SPEC.md §4, §5).
They are data, not prose, so severity calibration changes are reviewable diffs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.schemas.common import (
    ActionClass,
    DataClass,
    Severity,
    severity_from_rank,
    severity_rank,
)

#: Which IAM-style verbs authorize each action class. Deliberately 1:1: a tool exposing EXECUTE does
#: **not** thereby expose DEPLOY. Arguing that equivalence is the agentic layer's job, and any such
#: claim must be verified against the target's authorization before it is reported.
ACTION_TO_VERBS: dict[ActionClass, tuple[str, ...]] = {
    ActionClass.READ: ("read",),
    ActionClass.WRITE: ("write",),
    ActionClass.CREATE: ("create",),
    ActionClass.DELETE: ("delete",),
    ActionClass.EXECUTE: ("execute",),
    ActionClass.DEPLOY: ("deploy",),
    ActionClass.ROLLBACK: ("rollback",),
    ActionClass.ROTATE: ("rotate",),
    ActionClass.GRANT: ("grant",),
    ActionClass.REVOKE: ("revoke",),
    ActionClass.DISCOVER: ("read",),
    ActionClass.EXFILTRATE: ("read",),
    ActionClass.DESTROY: ("delete",),
}

#: Base severity rank per (action, data class). Rank 0..4 maps to INFO..CRITICAL.
_SEV: dict[ActionClass, dict[DataClass, int]] = {
    ActionClass.READ: {
        DataClass.PUBLIC: 0,
        DataClass.NONE: 1,
        DataClass.INTERNAL: 2,
        DataClass.CONFIDENTIAL: 3,
        DataClass.CUSTOMER_PII: 3,
        DataClass.SECRET_MATERIAL: 4,
    },
    ActionClass.WRITE: {
        DataClass.PUBLIC: 1,
        DataClass.NONE: 2,
        DataClass.INTERNAL: 3,
        DataClass.CONFIDENTIAL: 3,
        DataClass.CUSTOMER_PII: 3,
        DataClass.SECRET_MATERIAL: 4,
    },
    ActionClass.CREATE: {
        DataClass.PUBLIC: 1,
        DataClass.NONE: 1,
        DataClass.INTERNAL: 2,
        DataClass.CONFIDENTIAL: 2,
        DataClass.CUSTOMER_PII: 2,
        DataClass.SECRET_MATERIAL: 3,
    },
    ActionClass.DELETE: {
        DataClass.PUBLIC: 1,
        DataClass.NONE: 2,
        DataClass.INTERNAL: 2,
        DataClass.CONFIDENTIAL: 3,
        DataClass.CUSTOMER_PII: 3,
        DataClass.SECRET_MATERIAL: 3,
    },
    ActionClass.EXECUTE: {
        DataClass.PUBLIC: 2,
        DataClass.NONE: 2,
        DataClass.INTERNAL: 3,
        DataClass.CONFIDENTIAL: 3,
        DataClass.CUSTOMER_PII: 3,
        DataClass.SECRET_MATERIAL: 4,
    },
    ActionClass.DEPLOY: {
        DataClass.PUBLIC: 2,
        DataClass.NONE: 2,
        DataClass.INTERNAL: 3,
        DataClass.CONFIDENTIAL: 3,
        DataClass.CUSTOMER_PII: 3,
        DataClass.SECRET_MATERIAL: 4,
    },
    ActionClass.ROLLBACK: {
        DataClass.PUBLIC: 0,
        DataClass.NONE: 1,
        DataClass.INTERNAL: 1,
        DataClass.CONFIDENTIAL: 1,
        DataClass.CUSTOMER_PII: 1,
        DataClass.SECRET_MATERIAL: 2,
    },
    ActionClass.ROTATE: {
        DataClass.PUBLIC: 1,
        DataClass.NONE: 2,
        DataClass.INTERNAL: 2,
        DataClass.CONFIDENTIAL: 3,
        DataClass.CUSTOMER_PII: 3,
        DataClass.SECRET_MATERIAL: 3,
    },
    ActionClass.GRANT: dict.fromkeys(DataClass, 4),
    ActionClass.REVOKE: dict.fromkeys(DataClass, 3),
    ActionClass.DISCOVER: dict.fromkeys(DataClass, 0),
    ActionClass.EXFILTRATE: {
        DataClass.PUBLIC: 1,
        DataClass.NONE: 1,
        DataClass.INTERNAL: 2,
        DataClass.CONFIDENTIAL: 3,
        DataClass.CUSTOMER_PII: 4,
        DataClass.SECRET_MATERIAL: 4,
    },
    ActionClass.DESTROY: dict.fromkeys(DataClass, 4),
}

#: Environment tier rank reduction applied to the base rank.
TIER_RANK_SHIFT: dict[str, int] = {
    "development": -1,
    "testing": -1,
    "staging": 0,
    "production": 0,
    "shared": 0,
    "unknown": 0,
}


def base_severity(action: ActionClass, data_class: DataClass) -> Severity:
    """Base severity for an action against a resource of the given data class."""
    return severity_from_rank(_SEV.get(action, _SEV[ActionClass.READ]).get(data_class, 2))


#: Blocker kinds that reduce severity, and the actions they affect. A blocker only downgrades when it
#: is in scope, applies to the action, and is relevant to the target's environment.
BLOCKER_SEVERITY_DOWNGRADE: dict[str, tuple[str, ...]] = {
    "approval_gate": ("DEPLOY", "DELETE", "EXECUTE", "GRANT", "DESTROY"),
    "dlp": ("READ", "EXFILTRATE"),
    "allow_list": ("EXECUTE",),
    "output_masking": ("READ",),
}


@dataclass(frozen=True)
class SeverityAssessment:
    """Severity plus the rule ids that produced it, so the report can justify the band."""

    severity: Severity
    basis: list[str]

    @property
    def rank(self) -> int:
        return severity_rank(self.severity)


#: Deterministic keyword hints. These never create a capability on their own; they flag tools whose
#: declared actions may understate what the tool can do, which is what the agentic layer must then
#: argue using verified evidence.
_ACTION_HINTS: tuple[tuple[ActionClass, re.Pattern[str]], ...] = (
    (ActionClass.DELETE, re.compile(r"(?i)\b(delete|drop|truncate|purge|destroy)\w*\b")),
    (
        ActionClass.EXECUTE,
        re.compile(r"(?i)\b(execute|exec|shell|command|script|eval|invoke)\w*\b"),
    ),
    (ActionClass.GRANT, re.compile(r"(?i)\b(grant|attach|role|privilege|permission)\w*\b")),
    (ActionClass.WRITE, re.compile(r"(?i)\b(write|update|modify|patch|mutate|put)\w*\b")),
    (ActionClass.DEPLOY, re.compile(r"(?i)\b(deploy|release|publish|promote|rollout)\w*\b")),
    (ActionClass.ROTATE, re.compile(r"(?i)\b(rotate|revoke|rename)\w*\b")),
    (ActionClass.READ, re.compile(r"(?i)\b(read|get|list|describe|query|fetch|select)\w*\b")),
)

#: Phrases indicating that a tool's prose claims authority the structured data may not support.
AUTHORITY_CLAIM_PATTERN = re.compile(
    r"(?i)\b(full|admin|administrator|root|unrestricted|all)\b[^.\n]{0,40}\b"
    r"(access|privilege|permission|right|control)"
)


def keyword_action_hints(text: str) -> list[ActionClass]:
    """Candidate actions implied by free text (tool name, description, or schema)."""
    if not text:
        return []
    hints: list[ActionClass] = []
    for action, pattern in _ACTION_HINTS:
        if pattern.search(text) and action not in hints:
            hints.append(action)
    return hints


def undeclared_action_hints(tool: object) -> dict[ActionClass, str]:
    """Actions implied by a tool's prose but absent from its structured declaration.

    These are *review material*, never capabilities: they tell the agentic layer where to look and
    they justify the ``needs_llm_review`` flag on the tool's action evidence.
    """
    text = " ".join(
        filter(
            None,
            [
                getattr(tool, "name", ""),
                getattr(tool, "description_untrusted", None) or "",
                str(getattr(tool, "input_schema", "")),
            ],
        )
    )
    declared = {action.value for action in getattr(tool, "actions", [])}
    hints: dict[ActionClass, str] = {}
    for action in keyword_action_hints(text):
        if action.value not in declared:
            hints[action] = text[:200]
    return hints
