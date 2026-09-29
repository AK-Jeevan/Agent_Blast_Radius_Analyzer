"""Shared enumerations, the trust-tagged ``Source`` model, and severity algebra.

Design rules implemented here (docs/PHASE_0_PROBLEM_DEFINITION.md):

* Every text-bearing field that can come from an untrusted origin is wrapped in ``Source`` with
  ``trusted=False``; such text is *data only* and may never enter an instruction position.
* ``None`` means UNKNOWN. ``VerificationStatus`` distinguishes ``unverified`` from
  ``contradicted`` explicitly instead of collapsing both into "no".
"""

from __future__ import annotations

from enum import Enum, StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.tolerance import tolerant_missing


class SourceKind(StrEnum):
    """Where a piece of information came from (drives trust and evidence provenance)."""

    CONFIG = "config"
    INVENTORY = "inventory"
    IAM_EXPORT = "iam_export"
    NETPOL = "netpol"
    MCP_METADATA = "mcp_metadata"
    TOOL_DESCRIPTION = "tool_description"
    ENV_MANIFEST = "env_manifest"
    REPO_FILE = "repo_file"
    INSTRUCTIONS = "instructions"
    LOGS = "logs"
    DOCS = "docs"
    SCENARIO = "scenario"
    SYNTHETIC = "synthetic"
    DERIVED = "derived"
    USER_INPUT = "user_input"


class Source(BaseModel):
    """Provenance plus trust label for any input fact or untrusted text."""

    model_config = ConfigDict(frozen=True)

    kind: SourceKind = SourceKind.USER_INPUT
    ref: str = "unspecified"
    trusted: bool = False

    @property
    def untrusted(self) -> bool:
        return not self.trusted


class EnvironmentTier(StrEnum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)


#: Severity multipliers per environment tier (docs/ANALYSIS_ENGINE_SPEC.md §4).
TIER_MULTIPLIER: dict[EnvironmentTier, float] = {
    EnvironmentTier.DEVELOPMENT: 0.40,
    EnvironmentTier.TESTING: 0.50,
    EnvironmentTier.STAGING: 0.75,
    EnvironmentTier.PRODUCTION: 1.00,
    EnvironmentTier.UNKNOWN: 0.60,
}


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


#: Ordered least -> most severe. Index arithmetic implements upgrade/downgrade/cap.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def severity_rank(severity: Severity) -> int:
    return SEVERITY_ORDER.index(severity)


def severity_from_rank(rank: int) -> Severity:
    """Clamp a rank into the ladder so caps/floors can never index out of range."""
    return SEVERITY_ORDER[max(0, min(rank, len(SEVERITY_ORDER) - 1))]


def max_severity(*severities: Severity | None) -> Severity:
    ranks = [severity_rank(s) for s in severities if s is not None]
    return severity_from_rank(max(ranks)) if ranks else Severity.INFO


def downgrade(severity: Severity, steps: int = 1) -> Severity:
    return severity_from_rank(severity_rank(severity) - abs(steps))


def upgrade(severity: Severity, steps: int = 1) -> Severity:
    return severity_from_rank(severity_rank(severity) + abs(steps))


def cap_severity(severity: Severity, ceiling: Severity) -> Severity:
    """Apply a ceiling (used for uncertainty caps such as unresolved blockers)."""
    return severity_from_rank(min(severity_rank(severity), severity_rank(ceiling)))


class VerificationStatus(StrEnum):
    """How well supported a claim is. Ordinal: higher = stronger evidence of reality."""

    CONTRADICTED = "contradicted"
    UNVERIFIED = "unverified"
    POSSIBLE = "possible"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"


STATUS_ORDER: tuple[VerificationStatus, ...] = (
    VerificationStatus.CONTRADICTED,
    VerificationStatus.UNVERIFIED,
    VerificationStatus.POSSIBLE,
    VerificationStatus.PROBABLE,
    VerificationStatus.CONFIRMED,
)

#: Hard ceiling on reported confidence per status (docs/ANALYSIS_ENGINE_SPEC.md §6).
STATUS_CONFIDENCE_CEILING: dict[VerificationStatus, float] = {
    VerificationStatus.CONTRADICTED: 0.10,
    VerificationStatus.UNVERIFIED: 0.35,
    VerificationStatus.POSSIBLE: 0.55,
    VerificationStatus.PROBABLE: 0.85,
    VerificationStatus.CONFIRMED: 1.00,
}

#: Severity ceiling derived from the actionable status (docs/ANALYSIS_ENGINE_SPEC.md §4).
STATUS_SEVERITY_CEILING: dict[VerificationStatus, Severity] = {
    VerificationStatus.CONTRADICTED: Severity.INFO,
    VerificationStatus.UNVERIFIED: Severity.MEDIUM,
    VerificationStatus.POSSIBLE: Severity.MEDIUM,
    VerificationStatus.PROBABLE: Severity.HIGH,
    VerificationStatus.CONFIRMED: Severity.CRITICAL,
}


def status_rank(status: VerificationStatus) -> int:
    return STATUS_ORDER.index(status)


def weakest_status(*statuses: VerificationStatus) -> VerificationStatus:
    """The least-supported status among the inputs (used to aggregate a path)."""
    if not statuses:
        return VerificationStatus.UNVERIFIED
    return STATUS_ORDER[min(status_rank(s) for s in statuses)]


class Confidence(BaseModel):
    """Reported confidence *with* the evidence that produced it (never a bare number)."""

    model_config = ConfigDict(frozen=True)

    value: float = Field(ge=0.0, le=1.0, default=0.0)
    facts: int = 0
    inferences: int = 0
    hypotheses: int = 0
    basis: list[str] = Field(default_factory=list)

    @property
    def evidence_count(self) -> int:
        return self.facts + self.inferences + self.hypotheses


class ActionClass(StrEnum):
    """Closed action vocabulary (docs/PHASE_0_PROBLEM_DEFINITION.md §5).

    Deliberately *not* tolerant: a capability is only ever reported with an action from this list, so
    an unrecognised value must fail validation rather than degrade into something that looks safe.
    """

    READ = "READ"
    WRITE = "WRITE"
    CREATE = "CREATE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    DEPLOY = "DEPLOY"
    ROLLBACK = "ROLLBACK"
    ROTATE = "ROTATE"
    GRANT = "GRANT"
    REVOKE = "REVOKE"
    DISCOVER = "DISCOVER"
    # Derived composites (never declared in input; computed by the engine):
    EXFILTRATE = "EXFILTRATE"  # READ + egress to outside the boundary + no DLP blocker
    DESTROY = "DESTROY"  # DELETE + no backup + no restore/rollback path

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)

    @classmethod
    def known_actions(cls) -> tuple[str, ...]:
        """Every action the analyzer understands, for error messages and API introspection."""
        return tuple(member.value for member in cls)


#: Actions whose severity is adjusted by recoverability (docs/ANALYSIS_ENGINE_SPEC.md §4).
DESTRUCTIVE_ACTIONS: frozenset[ActionClass] = frozenset(
    {ActionClass.DELETE, ActionClass.EXECUTE, ActionClass.DESTROY}
)

#: Actions that represent privilege escalation; discovering one requires re-running the closure.
ESCALATION_ACTIONS: frozenset[ActionClass] = frozenset(
    {ActionClass.GRANT, ActionClass.REVOKE, ActionClass.ROTATE}
)


class Recoverability(StrEnum):
    RECOVERABLE = "recoverable"
    DIFFICULT = "difficult"
    POTENTIALLY_IRREVERSIBLE = "potentially_irreversible"
    UNKNOWN = "unknown"


class BlockerKind(StrEnum):
    APPROVAL_GATE = "approval_gate"
    DRY_RUN = "dry_run"
    ALLOW_LIST = "allow_list"
    RATE_LIMIT = "rate_limit"
    DLP = "dlp"
    OUTPUT_MASKING = "output_masking"
    NETWORK_POLICY = "network_policy"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)


class ConditionKind(StrEnum):
    MFA = "mfa"
    SOURCE_IP_CIDR = "source_ip_cidr"
    TIME_WINDOW = "time_window"
    APPROVAL_REQUIRED = "approval_required"
    RESOURCE_TAG = "resource_tag"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)


class Relationship(StrEnum):
    """Typed, directed graph edges (docs/DATA_MODEL.md §8)."""

    USES = "USES"
    REQUIRES = "REQUIRES"
    AUTHORIZES = "AUTHORIZES"
    ASSUMES = "ASSUMES"
    HAS_ACCESS_TO = "HAS_ACCESS_TO"
    CAN_READ = "CAN_READ"
    CAN_WRITE = "CAN_WRITE"
    CAN_DELETE = "CAN_DELETE"
    CAN_EXECUTE = "CAN_EXECUTE"
    CAN_DEPLOY = "CAN_DEPLOY"
    DEPENDS_ON = "DEPENDS_ON"
    DEPLOYS_TO = "DEPLOYS_TO"
    CONNECTS_TO = "CONNECTS_TO"
    DISCOVERS = "DISCOVERS"
    ENABLES = "ENABLES"
    ESCALATES_TO = "ESCALATES_TO"
    BACKS_UP = "BACKS_UP"
    GATED_BY = "GATED_BY"
    IN_ENVIRONMENT = "IN_ENVIRONMENT"
    CONTRADICTS = "CONTRADICTS"


#: Read-style relationships used when resolving "what rows does the graph expose".
ACCESS_RELATIONSHIPS: frozenset[Relationship] = frozenset(
    {
        Relationship.HAS_ACCESS_TO,
        Relationship.CAN_READ,
        Relationship.CAN_WRITE,
        Relationship.CAN_DELETE,
        Relationship.CAN_EXECUTE,
        Relationship.CAN_DEPLOY,
        Relationship.AUTHORIZES,
    }
)

#: Action -> graph relationship produced when a capability is confirmed.
ACTION_TO_RELATIONSHIP: dict[ActionClass, Relationship] = {
    ActionClass.READ: Relationship.CAN_READ,
    ActionClass.WRITE: Relationship.CAN_WRITE,
    ActionClass.DELETE: Relationship.CAN_DELETE,
    ActionClass.EXECUTE: Relationship.CAN_EXECUTE,
    ActionClass.DEPLOY: Relationship.CAN_DEPLOY,
}


class NetworkEgress(StrEnum):
    INTERNAL = "internal"
    VPN = "vpn"
    INTERNET = "internet"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)


class ResourceType(StrEnum):
    SERVICE = "service"
    DATABASE = "database"
    BUCKET = "bucket"
    REPOSITORY = "repository"
    PIPELINE = "pipeline"
    # The value reads like a password to B105; it is the name of a resource *type*, matched against
    # data/resources. pyproject.toml exempts this same false positive for this file as ruff S105.
    SECRET_STORE = "secret_store"  # nosec B105
    QUEUE = "queue"
    COMPUTE = "compute"
    ENDPOINT = "endpoint"
    DNS = "dns"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)


class DataClass(StrEnum):
    NONE = "none"
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CUSTOMER_PII = "customer_pii"
    # A label for the data class, not credential material -- see the note on ResourceType above.
    SECRET_MATERIAL = "secret_material"  # nosec B105
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)


#: Data classes that trigger egress inspection when a DLP blocker is in scope.
SENSITIVE_DATA_CLASSES: frozenset[DataClass] = frozenset(
    {DataClass.CONFIDENTIAL, DataClass.CUSTOMER_PII, DataClass.SECRET_MATERIAL}
)


class CredentialType(StrEnum):
    # Every value here names a credential *kind* from the corpus vocabulary; none of them is material.
    # B105 cannot tell a label from a secret, so each line carries its own marker rather than a
    # rule-wide skip that would also silence a genuinely hardcoded password elsewhere in app/.
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"  # nosec B105
    OAUTH_TOKEN = "oauth_token"  # nosec B105
    SERVICE_TOKEN = "service_token"  # nosec B105
    ENV_VAR = "env_var"
    MOUNTED_SECRET = "mounted_secret"  # nosec B105
    TEMP_CREDENTIAL = "temp_credential"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)


class IdentityType(StrEnum):
    SERVICE_ACCOUNT = "service_account"
    IAM_ROLE = "iam_role"
    OAUTH_CLIENT = "oauth_client"
    API_IDENTITY = "api_identity"
    GITHUB_APP = "github_app"
    USER = "user"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)


class Provider(StrEnum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    GITHUB = "github"
    INTERNAL = "internal"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> Enum | None:
        return tolerant_missing(cls, value)


class RunMode(StrEnum):
    """The four ablation configurations (docs/EVALUATION_PLAN.md §4)."""

    A_DETERMINISTIC = "A_deterministic"
    B_INTERPRET = "B_interpret"
    C_AGENTIC = "C_agentic"
    D_FULL = "D_full"


class EvidenceKind(StrEnum):
    FACT = "fact"
    INFERENCE = "inference"
    HYPOTHESIS = "hypothesis"
    CONTRADICTION = "contradiction"


#: How an action was determined for a tool: name match, schema inspection, or LLM interpretation.
class ActionEvidenceMethod(StrEnum):
    NAME_MATCH = "name_match"
    SCHEMA_INSPECTION = "schema_inspection"
    DESCRIPTION_KEYWORD = "description_keyword"
    EXPLICIT_DECLARATION = "explicit_declaration"
    LLM_INTERPRETATION = "llm_interpretation"
    DERIVED = "derived"


#: Confidence assigned to each determination method (LLM output can never reach "confirmed").
METHOD_CONFIDENCE: dict[ActionEvidenceMethod, float] = {
    ActionEvidenceMethod.EXPLICIT_DECLARATION: 0.95,
    ActionEvidenceMethod.SCHEMA_INSPECTION: 0.70,
    ActionEvidenceMethod.NAME_MATCH: 0.65,
    ActionEvidenceMethod.DESCRIPTION_KEYWORD: 0.55,
    ActionEvidenceMethod.LLM_INTERPRETATION: 0.45,
    ActionEvidenceMethod.DERIVED: 0.90,
}
