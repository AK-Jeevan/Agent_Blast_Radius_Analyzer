"""Input compatibility policy: how the analyzer reacts to data it does not recognise.

The analyzer is fed files that other people and other tools produce, and those files will drift
(a new field, a renamed enum value, a newer schema revision). A security tool must not fall over
when that happens — and it must not silently *guess* either. So there are two modes, chosen by the
caller, and the choice is visible in the output:

``tolerant`` (default)
    Unknown *fields* are ignored, unknown *enum values* degrade to their ``UNKNOWN`` member, and a
    fragment from a newer ``schema_version`` still loads. Every relaxation is recorded as a warning
    so the report can say what it did not understand.

``strict``
    Unknown fields and unknown enum values are errors. CI runs the corpus in strict mode so that
    schema drift is caught in a pull request rather than discovered in production.

The asymmetry is deliberate: *structure* may drift, but *meaning* may not be invented. A capability
still requires a known action, a known target, real authorization, and a real network path — no
amount of tolerance weakens that, because those checks are code, not configuration.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import ConfigDict

#: Current schema revision of the data corpus. A fragment may declare a higher revision: it will load
#: in tolerant mode (with a warning) and fail in strict mode.
SCHEMA_VERSION = 1

STRICT = "strict"
TOLERANT = "tolerant"
Mode = str


def input_config(**overrides: Any) -> ConfigDict:
    """Config for models that parse *external* input: unknown fields are ignored, names allowed."""
    config: dict[str, Any] = {
        "extra": "ignore",
        "validate_by_name": True,
        "validate_by_alias": True,
    }
    config.update(overrides)
    # ConfigDict is a TypedDict, so mypy can neither verify **expansion of an arbitrary dict against
    # its keys nor type the construction as anything but Any. The call is correct -- every key above is
    # a real ConfigDict key, and the overrides come from this package rather than from user input --
    # so both codes are suppressed here rather than leaving the strict check to complain.
    return ConfigDict(**config)  # type: ignore[typeddict-item, no-any-return]


def output_config(**overrides: Any) -> ConfigDict:
    """Config for models we emit: unknown fields are a bug, so they are rejected."""
    config: dict[str, Any] = {
        "extra": "forbid",
        "validate_by_name": True,
        "validate_by_alias": True,
    }
    config.update(overrides)
    return ConfigDict(**config)  # type: ignore[typeddict-item, no-any-return]


#: Convenience spellings people actually use in configuration files.
ENUM_ALIASES: dict[tuple[str, str], str] = {
    ("EnvironmentTier", "dev"): "development",
    ("EnvironmentTier", "prod"): "production",
    ("EnvironmentTier", "production"): "production",
    ("EnvironmentTier", "stage"): "staging",
    ("EnvironmentTier", "test"): "testing",
    ("DataClass", "pii"): "customer_pii",
    ("DataClass", "confidential_data"): "confidential",
    ("ResourceType", "api"): "service",
    ("ResourceType", "postgres"): "database",
    ("ResourceType", "s3"): "bucket",
    ("CredentialType", "token"): "service_token",
    ("CredentialType", "secret"): "mounted_secret",
    ("NetworkEgress", "public"): "internet",
    ("BlockerKind", "approval"): "approval_gate",
    ("BlockerKind", "human_approval"): "approval_gate",
    ("Provider", "amazon"): "aws",
}


def resolve_enum_value(enum_cls: type[Enum], value: object) -> Enum | None:
    """Resolve a value against an enum, tolerating case, dashes, spaces, and known aliases.

    Returns ``None`` when the value cannot be resolved; the caller decides whether to raise. Aliases
    are resolved by member *value*, not by member name -- ``DataClass("pii")`` is an alias of the
    value ``customer_pii`` whose attribute name is ``CUSTOMER_PII``.
    """
    if isinstance(value, enum_cls):
        return value
    if not isinstance(value, str):
        return None
    normalised = value.strip().lower().replace("-", "_").replace(" ", "_")
    for member in enum_cls:
        if str(member.value).lower() == normalised:
            return member
    alias = ENUM_ALIASES.get((enum_cls.__name__, normalised))
    if alias is not None:
        for member in enum_cls:
            if str(member.value).lower() == alias.lower():
                return member
    return None


def is_direct_enum_value(enum_cls: type[Enum], value: object) -> bool:
    """True when ``value`` matches a member exactly, with no aliasing or degradation involved."""
    if not isinstance(value, str):
        return isinstance(value, enum_cls)
    normalised = value.strip().lower()
    return any(str(member.value).lower() == normalised for member in enum_cls)


def tolerant_missing(enum_cls: type[Enum], value: object) -> Enum | None:
    """``_missing_`` implementation: alias-aware, degrading to ``UNKNOWN`` when one exists.

    An enum without an ``UNKNOWN`` member (for example :class:`ActionClass`, where a silent "unknown
    action" would be unsafe) returns ``None``, so validation still fails loudly.
    """
    resolved = resolve_enum_value(enum_cls, value)
    if resolved is not None:
        return resolved
    # No suppression needed: `__members__` and `__getitem__` are part of the Enum API and mypy accepts
    # both on a `type[Enum]`. An earlier version carried `# type: ignore` comments here that strict mode
    # correctly flagged as unused -- dead suppressions are worse than none, because they hide the day a
    # real error appears on the same line.
    if "UNKNOWN" in enum_cls.__members__:
        return enum_cls["UNKNOWN"]
    return None


class CompatibilityWarning(str):
    """A single, reportable note about something the analyzer had to tolerate or ignore."""
