"""Input entity schemas: Environment, Identity, Tool, Credential, Resource, Permission,
NetworkEdge, Blocker, Agent, InstructionDoc.

These mirror ``docs/DATA_MODEL.md`` field for field. Two invariants hold by construction:

* ``None`` means UNKNOWN (never false, never allowed).
* Untrusted text lives in explicit ``*_untrusted`` fields wrapped by
  :class:`~app.schemas.common.Source`, so the engine can quarantine it structurally.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.common import (
    METHOD_CONFIDENCE,
    ActionClass,
    ActionEvidenceMethod,
    BlockerKind,
    ConditionKind,
    CredentialType,
    DataClass,
    EnvironmentTier,
    IdentityType,
    NetworkEgress,
    Provider,
    Recoverability,
    ResourceType,
    Source,
)
from app.schemas.tolerance import input_config


class Fragment(BaseModel):
    """Common base for every loadable data fragment.

    Parsed with the *tolerant* input policy: a fragment written by a newer tool may carry fields or
    enum values this version does not know, and they are ignored (with a warning) rather than
    crashing a whole analysis. ``schema_version`` lets a producer declare its revision.
    """

    model_config = input_config(extra="ignore")

    id: str
    source: Source = Field(default_factory=Source)
    schema_version: int | None = Field(
        default=None,
        description="Revision of the producer's schema; newer than SCHEMA_VERSION is tolerated",
    )


class Environment(Fragment):
    name: str
    tier: EnvironmentTier = EnvironmentTier.UNKNOWN
    criticality: int = Field(default=1, ge=0, le=3)
    multiplier: float | None = Field(default=None, gt=0.0, le=2.0)
    boundary: str | None = None
    notes_untrusted: str | None = None


class Identity(Fragment):
    type: IdentityType = IdentityType.UNKNOWN
    name: str
    environment: str | None = None
    provider: Provider = Provider.UNKNOWN
    principal_ref: str | None = Field(default=None, repr=False)
    trusted_for: list[str] = Field(default_factory=list)
    assumable_by: list[str] = Field(default_factory=list)
    notes_untrusted: str | None = None


class ActionEvidence(BaseModel):
    """Provenance for a claimed tool action (docs/DATA_MODEL.md §3)."""

    model_config = input_config()

    action: ActionClass
    method: ActionEvidenceMethod = ActionEvidenceMethod.NAME_MATCH
    span: str | None = None
    needs_llm_review: bool = False
    notes: str | None = None

    @property
    def method_confidence(self) -> float:
        return METHOD_CONFIDENCE.get(self.method, 0.4)


class TargetSelector(BaseModel):
    """How a tool picks its target; ``closed_vocabulary=False`` means arbitrary targets."""

    model_config = input_config()

    param: str | None = None
    values: list[str] = Field(default_factory=list)
    closed_vocabulary: bool = True


class PreconditionKind(StrEnum):
    CREDENTIAL_PRESENT = "credential_present"
    NETWORK_REACHABLE = "network_reachable"
    SESSION_FACT = "session_fact"
    RESOURCE_EXISTS = "resource_exists"


class Precondition(BaseModel):
    model_config = input_config()

    kind: PreconditionKind
    ref: str
    note: str | None = None


class Tool(Fragment):
    name: str
    description_untrusted: str | None = None
    actions: list[ActionClass] = Field(default_factory=list)
    action_evidence: list[ActionEvidence] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    target_selector: TargetSelector = Field(default_factory=TargetSelector)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    requires_credentials: list[str] = Field(default_factory=list)
    side_effect: bool = False
    destructive: bool = False
    reversible: bool | None = None
    preconditions: list[Precondition] = Field(default_factory=list)
    discovery_capability: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    is_mcp: bool = False
    notes_untrusted: str | None = None

    @model_validator(mode="after")
    def _ensure_action_evidence(self) -> Tool:
        """Every declared action must carry a provenance record.

        Without this, an action could enter the analysis with no traceable basis, which would make
        the "evidence or it didn't happen" guarantee unenforceable.
        """
        declared = {action.value for action in self.actions}
        evidenced = {item.action.value for item in self.action_evidence}
        missing = declared - evidenced
        if missing:
            self.action_evidence = [
                *self.action_evidence,
                *[
                    ActionEvidence(
                        action=ActionClass(value),
                        method=ActionEvidenceMethod.EXPLICIT_DECLARATION,
                    )
                    for value in sorted(missing)
                ],
            ]
        return self


class Credential(Fragment):
    """Credential metadata only. There is deliberately no value field anywhere."""

    type: CredentialType = CredentialType.UNKNOWN
    secret_ref: str = Field(default="", repr=False)
    has_value: bool | None = None
    issuer: str | None = None
    scope: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    audience: list[str] = Field(default_factory=list)
    expires_at: str | None = None
    assumed_identity: str | None = None
    discoverable_via: list[str] = Field(default_factory=list)
    max_privilege_available: bool = False
    notes_untrusted: str | None = None


class RecoveryProfile(BaseModel):
    """Recovery facts for a resource. ``None`` fields are UNKNOWN, not "safe"."""

    model_config = input_config()

    recoverability: Recoverability = Recoverability.UNKNOWN
    mechanisms: list[str] = Field(default_factory=list)
    latest_recovery_point: str | None = None
    mean_time_to_recover: str | None = None
    evidence: list[str] = Field(default_factory=list)


class Resource(Fragment):
    name: str
    type: ResourceType = ResourceType.UNKNOWN
    environment: str | None = None
    data_class: DataClass = DataClass.NONE
    criticality: int = Field(default=1, ge=0, le=3)
    recovery: RecoveryProfile | None = None
    dependents: list[str] = Field(default_factory=list)
    backs_up: list[str] = Field(default_factory=list)
    notes_untrusted: str | None = None


class PermissionCondition(BaseModel):
    model_config = input_config()

    kind: ConditionKind
    value: Any = None
    note: str | None = None


class Permission(Fragment):
    principal: str
    effect: str = Field(default="allow", pattern="^(allow|deny)$")
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    conditions: list[PermissionCondition] = Field(default_factory=list)
    via: str | None = None
    evidence_note: str | None = None
    notes_untrusted: str | None = None


class NetworkEdge(Fragment):
    """One directed reachability edge. ``from`` is the caller, ``target`` is the callee.

    ``reachable``, ``authenticated``, ``authorized`` and ``actionable`` are **four independent**
    truth values; the engine never collapses them (docs/DATA_MODEL.md §7).
    """

    from_id: str = Field(alias="from")
    target: str
    protocol: str | None = None
    egress: NetworkEgress = NetworkEgress.INTERNAL
    reachable: bool = True
    authenticated: bool | None = None
    authenticated_via: list[str] = Field(default_factory=list)
    boundary: str | None = None
    evidence_note: str | None = None
    notes_untrusted: str | None = None

    model_config = ConfigDict(extra="forbid", validate_by_name=True, validate_by_alias=True)


class Blocker(Fragment):
    name: str
    kind: BlockerKind
    applies_to_actions: list[ActionClass] = Field(default_factory=list)
    environments: list[str] = Field(default_factory=list)
    description_untrusted: str | None = None
    effect_note: str | None = None


class Agent(Fragment):
    name: str
    identity: str
    environment: str | None = None
    instructions: str | None = None
    tools: list[str] = Field(default_factory=list)
    mcp_servers: list[str] = Field(default_factory=list)
    credentials_present: list[str] = Field(default_factory=list)
    declared_purpose_untrusted: str | None = None


class InstructionDoc(Fragment):
    """A system prompt / instruction document of the analyzed agent.

    Its *content* is untrusted to the analyzer: it may itself contain an injection payload, and it
    never becomes an instruction to us.
    """

    name: str
    content_untrusted: str = ""
    intended_purpose: str | None = None
