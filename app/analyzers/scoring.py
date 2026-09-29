"""Severity and recovery scoring: table-driven, explainable, and never invented.

The formula (docs/ANALYSIS_ENGINE_SPEC.md §4):

```
rank = base(action, data_class)
rank += TIER_RANK_SHIFT[tier]                  # development/testing are one band lower
rank += CRITICALITY_RANK_SHIFT[criticality]    # non-production-critical targets are one lower
rank -= applicable blocker downgrades          # approval gate, DLP, allow-list, masking
rank += 1 if recoverability == difficult and action in {DELETE, EXECUTE, DESTROY}
cap  : criticality 0 -> LOW; status possible/unverified -> MEDIUM
force: potentially_irreversible + DELETE/DESTROY -> CRITICAL
```

Every result carries the rule ids that produced it, so the report can justify the band.
"""

from __future__ import annotations

from app.analyzers.taxonomy import (
    BLOCKER_SEVERITY_DOWNGRADE,
    TIER_RANK_SHIFT,
    SeverityAssessment,
    base_severity,
)
from app.schemas.common import (
    SEVERITY_ORDER,
    STATUS_SEVERITY_CEILING,
    ActionClass,
    Recoverability,
    Severity,
    VerificationStatus,
    cap_severity,
    severity_from_rank,
    severity_rank,
)
from app.schemas.entities import Resource

#: Rank adjustment from a target's declared criticality. Criticality 3 = platform-critical.
CRITICALITY_RANK_SHIFT: dict[int, int] = {0: -2, 1: -1, 2: -1, 3: 0}

#: Environment ids in the corpus map to environment names by suffix; the agent's own environment is
#: resolved from the input when available.
_ENV_ID_TO_NAME: dict[str, str] = {
    "env-dev": "development",
    "env-staging": "staging",
    "env-prod": "production",
    "env-shared": "shared",
}


def environment_name_for_id(environment_id: str) -> str:
    """Best-effort mapping from an environment id to its name (corpus convention)."""
    if environment_id in _ENV_ID_TO_NAME:
        return _ENV_ID_TO_NAME[environment_id]
    return environment_id.removeprefix("env-")


def blocker_in_environment(
    blocker_environments: list[str],
    target_environment: str | None,
) -> bool:
    """Whether a control scoped to these environments covers a target in this environment.

    An empty scope means *everywhere*: a control that names no environment is not thereby a control
    that applies nowhere. An unknown target environment is treated as in scope, so ambiguity can only
    ever add a control, never silently drop one.

    This is separated from :func:`blocker_applies` because the two questions are genuinely different.
    A caller holding a control a tool declared by id needs the environment half of the test without
    the kind half -- see ``app.analyzers.closure.applicable_blockers``.
    """
    if not blocker_environments or target_environment is None:
        return True
    names = {environment_name_for_id(item) for item in blocker_environments} | set(
        blocker_environments
    )
    return target_environment in names


def blocker_applies(
    blocker_kind: str,
    action: ActionClass,
    target_environment: str | None,
    blocker_environments: list[str],
) -> bool:
    """Whether a blocker downgrades this action against a target in this environment.

    This answers a question about a *kind*: does the downgrade table say this kind affects this
    action, here? ``False`` therefore conflates two different situations -- "the kind declares no
    effect on this action" and "the kind does, but the control is scoped to another environment" --
    which is why the scope test lives in :func:`blocker_in_environment` rather than inline here.
    """
    affected = BLOCKER_SEVERITY_DOWNGRADE.get(blocker_kind)
    if not affected or action.value not in affected:
        return False
    return blocker_in_environment(blocker_environments, target_environment)


def recovery_for(
    resource: Resource,
) -> tuple[Recoverability, list[str], list[str]]:
    """Return (recoverability, mechanisms, notes) from the resource's declared recovery profile."""
    profile = resource.recovery
    if profile is None:
        return Recoverability.UNKNOWN, [], [f"no_recovery_facts_for_{resource.id}"]
    mechanisms = list(profile.mechanisms)
    notes: list[str] = []
    recoverability = profile.recoverability
    if recoverability == Recoverability.UNKNOWN and mechanisms:
        recoverability = Recoverability.RECOVERABLE
    if not mechanisms:
        notes.append(f"no_recovery_mechanism_declared_for_{resource.id}")
    if profile.latest_recovery_point is None and mechanisms:
        notes.append(f"recovery_point_age_unknown_for_{resource.id}")
    return recoverability, mechanisms, notes


def assess_severity(
    action: ActionClass,
    resource: Resource,
    *,
    tier: str,
    status: VerificationStatus,
    recoverability: Recoverability,
    blocker_kinds: list[str] | None = None,
) -> SeverityAssessment:
    """Compute severity for one (action, target) pair with an explicit rule trace."""
    basis: list[str] = [f"BASE_{action.value}_{resource.data_class.value}"]
    rank = severity_rank(base_severity(action, resource.data_class))

    tier_shift = TIER_RANK_SHIFT.get(tier, 0)
    if tier_shift:
        rank += tier_shift
        basis.append(f"TIER_{tier.upper()}")

    criticality_shift = CRITICALITY_RANK_SHIFT.get(resource.criticality, 0)
    if criticality_shift:
        rank += criticality_shift
        basis.append(f"CRITICALITY_{resource.criticality}")

    for blocker_kind in sorted(blocker_kinds or []):
        if blocker_kind in BLOCKER_SEVERITY_DOWNGRADE:
            rank -= 1
            basis.append(f"BLOCKER_{blocker_kind.upper()}")
        else:
            basis.append(f"CONTROL_{blocker_kind.upper()}")

    if recoverability == Recoverability.DIFFICULT and action in {
        ActionClass.DELETE,
        ActionClass.EXECUTE,
        ActionClass.DESTROY,
    }:
        rank += 1
        basis.append("RECOVERY_DIFFICULT")

    severity = severity_from_rank(rank)

    if resource.criticality == 0:
        severity = cap_severity(severity, Severity.LOW)
        basis.append("CAP_CRITICALITY_0")
    if status in {VerificationStatus.POSSIBLE, VerificationStatus.UNVERIFIED}:
        severity = cap_severity(severity, Severity.MEDIUM)
        basis.append(f"CAP_STATUS_{status.value.upper()}")
    else:
        severity = cap_severity(severity, STATUS_SEVERITY_CEILING[status])
        basis.append(f"CAP_STATUS_{status.value.upper()}")
    if recoverability == Recoverability.POTENTIALLY_IRREVERSIBLE and action in {
        ActionClass.DELETE,
        ActionClass.DESTROY,
    }:
        severity = SEVERITY_ORDER[-1]
        basis.append("FORCE_IRREVERSIBLE")

    return SeverityAssessment(severity=severity, basis=sorted(set(basis)))
