"""Authorization evaluation: the deterministic heart of declared vs. effective.

Rules (docs/ANALYSIS_ENGINE_SPEC.md §2):

* **default deny** -- no matching allow means not authorized;
* **explicit deny wins** over any allow, regardless of specificity or order;
* wildcards are supported, and resource patterns match id, name, or environment;
* unmet or unverifiable conditions downgrade a decision; they never grant access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

from app.analyzers.taxonomy import ACTION_TO_VERBS
from app.schemas.analysis import AnalysisInput
from app.schemas.common import ActionClass
from app.schemas.entities import Permission, Resource


@dataclass(frozen=True)
class AuthzDecision:
    """One authorization decision, with the policies and conditions that produced it."""

    action: ActionClass
    resource_id: str
    allowed: bool
    reason: str  # "allow" | "deny" | "no_matching_allow"
    principals: tuple[str, ...] = ()
    policies: tuple[str, ...] = ()
    conditions_unknown: tuple[str, ...] = ()
    conditions_unmet: tuple[str, ...] = ()
    matched_verbs: tuple[str, ...] = ()

    @property
    def has_unknown_conditions(self) -> bool:
        return bool(self.conditions_unknown)

    @property
    def needs_downgrade(self) -> bool:
        return bool(self.conditions_unknown or self.conditions_unmet)


@dataclass
class PolicyEvaluator:
    """Evaluates structured permissions against (principal, action, resource) triples."""

    analysis_input: AnalysisInput
    _by_principal: dict[str, list[Permission]] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        for permission in self.analysis_input.permissions:
            self._by_principal.setdefault(permission.principal, []).append(permission)
        for policies in self._by_principal.values():
            policies.sort(key=lambda policy: policy.id)

    # --- matching helpers ---------------------------------------------------------------
    @staticmethod
    def _verb_matches(pattern: str, verb: str) -> bool:
        """Exact verb or global wildcard only.

        A qualified action such as ``read:logs`` does **not** authorize a bare ``read``: treating it
        as a family match silently inflates authority, which is precisely the failure mode this
        analyzer exists to detect (see S6, where it produced a phantom production data read).
        """
        pattern = pattern.strip().lower()
        return pattern in {"*", verb.strip().lower()}

    def verb_matches_any(self, patterns: list[str], verb: str) -> bool:
        return any(self._verb_matches(pattern, verb) for pattern in patterns)

    def _resource_matches(self, patterns: list[str], resource: Resource) -> bool:
        """Match a policy's resource patterns against id, name, or environment."""
        for pattern in patterns:
            stripped = pattern.strip()
            if stripped in {"*", resource.id, resource.name}:
                return True
            if fnmatch(resource.id, stripped) or fnmatch(resource.name, stripped):
                return True
            if resource.environment and (
                stripped == resource.environment or fnmatch(resource.environment, stripped)
            ):
                return True
        return False

    # --- evaluation ---------------------------------------------------------------------
    def evaluate(
        self,
        principals: tuple[str, ...],
        resource: Resource,
        action: ActionClass,
        *,
        via_credential: str | None = None,
    ) -> AuthzDecision:
        """Evaluate one action against one resource for the given principals.

        Asymmetry that matters:

        * an **allow** only counts when its ``via`` binding matches the credential actually being
          used (a policy bound to the CI token does not authorise calls made with another token);
        * a **deny** is evaluated without that restriction, because an explicit deny is a statement
          about the principal, not about one credential path.
        """
        verbs = ACTION_TO_VERBS.get(action, ("read",))
        allows: list[Permission] = []
        denies: list[Permission] = []
        matched_verbs: set[str] = set()

        for principal in principals:
            for policy in self._by_principal.get(principal, []):
                if not self._resource_matches(policy.resources, resource):
                    continue
                verb_hits = [verb for verb in verbs if self.verb_matches_any(policy.actions, verb)]
                if not verb_hits:
                    continue
                matched_verbs.update(verb_hits)
                if policy.effect == "deny":
                    denies.append(policy)
                elif policy.via is None or policy.via == via_credential:
                    allows.append(policy)

        if denies:
            return AuthzDecision(
                action=action,
                resource_id=resource.id,
                allowed=False,
                reason="deny",
                principals=principals,
                policies=tuple(sorted(policy.id for policy in denies)),
                matched_verbs=tuple(sorted(matched_verbs)),
            )
        if not allows:
            return AuthzDecision(
                action=action,
                resource_id=resource.id,
                allowed=False,
                reason="no_matching_allow",
                principals=principals,
            )

        unknown: list[str] = []
        unmet: list[str] = []
        for policy in allows:
            for condition in policy.conditions:
                label = f"{policy.id}:{condition.kind.value}"
                # Nothing in the MVP input can *prove* an MFA, IP, time, or tag condition, so the
                # condition stays unknown rather than being assumed satisfied or violated.
                if condition.kind.value == "approval_required":
                    unmet.append(label)
                else:
                    unknown.append(label)

        return AuthzDecision(
            action=action,
            resource_id=resource.id,
            allowed=True,
            reason="allow",
            principals=principals,
            policies=tuple(sorted(policy.id for policy in allows)),
            conditions_unknown=tuple(sorted(set(unknown))),
            conditions_unmet=tuple(sorted(set(unmet))),
            matched_verbs=tuple(sorted(matched_verbs)),
        )

    def declared_actions(
        self, principals: tuple[str, ...], resource: Resource
    ) -> list[ActionClass]:
        """Actions the *declared* configuration claims, ignoring deny and reachability.

        This is layer L0: what the configuration says, kept separate from what is effective so the
        report can expose the difference instead of collapsing it.
        """
        derived = {ActionClass.DISCOVER, ActionClass.EXFILTRATE, ActionClass.DESTROY}
        declared: list[ActionClass] = []
        for action in ActionClass:
            if action in derived:
                continue
            verbs = ACTION_TO_VERBS.get(action, ())
            for principal in principals:
                policies = self._by_principal.get(principal, [])
                if any(
                    policy.effect == "allow"
                    and self._resource_matches(policy.resources, resource)
                    and any(self.verb_matches_any(policy.actions, verb) for verb in verbs)
                    for policy in policies
                ):
                    declared.append(action)
                    break
        return declared

    def deny_exists(self, principals: tuple[str, ...], resource: Resource) -> bool:
        """Whether any explicit deny mentions this principal/resource pair for any action."""
        for principal in principals:
            for policy in self._by_principal.get(principal, []):
                if policy.effect == "deny" and self._resource_matches(policy.resources, resource):
                    return True
        return False

    def policies_for(self, principals: tuple[str, ...], resource: Resource) -> list[Permission]:
        """All policies (allow and deny) that mention these principals and this resource."""
        found: list[Permission] = []
        for principal in principals:
            for policy in self._by_principal.get(principal, []):
                if self._resource_matches(policy.resources, resource):
                    found.append(policy)
        return found
