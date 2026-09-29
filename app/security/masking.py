"""Secret masking and secret-pattern detection: the boundary where secrets stop.

Three guarantees, all enforced by tests:

1. **Secret values are never modelled.** :class:`~app.schemas.entities.Credential` has no value
   field; only ``secret_ref`` locators exist.
2. **Anything that looks like a secret is redacted before it can travel** into state, prompts,
   logs, evidence, reports, or the API response.
3. **Secret-looking material in the repository fails the build** (see
   ``tests/security/test_no_secrets.py``), so leaks are caught in CI rather than in production.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "[REDACTED]"

#: Ordered patterns; first match wins. Kept intentionally narrow to avoid masking ordinary prose.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nvidia_api_key", re.compile(r"\bnvapi-[A-Za-z0-9_\-]{16,}\b")),
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    (
        "generic_kv_secret",
        re.compile(
            r"(?i)\b(?:secret|token|password|passwd|api[_-]?key)\b\s*[:=]\s*"
            r"['\"]?(?!\[REDACTED\])[A-Za-z0-9_\-/+.]{12,}['\"]?"
        ),
    ),
)

#: Key names whose *values* must never be emitted, even if the pattern scan misses them.
SENSITIVE_KEY_MARKERS: tuple[str, ...] = (
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "authorization",
    "bearer",
)

SAFE_KEYS: frozenset[str] = frozenset(
    {
        "secret_ref",
        "credential_id",
        "credential_ids",
        "requires_credentials",
        "authenticated_via",
        "discoverable_via",
        "has_value",
        "api_key_configured",
        "token_count",
    }
)


def is_sensitive_key(key: str) -> bool:
    """True when a mapping key names something whose value must not be emitted."""
    lowered = key.lower()
    if lowered in SAFE_KEYS:
        return False
    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)


def redact_text(text: str) -> str:
    """Replace every secret-looking substring with ``[REDACTED]``."""
    if not text:
        return text
    redacted = text
    for _pattern_name, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def detect_secret_patterns(text: str) -> list[str]:
    """Return the *names* of patterns found (never the matched secret material itself)."""
    if not text:
        return []
    return [name for name, pattern in SECRET_PATTERNS if pattern.search(text)]


def contains_secret(text: str) -> bool:
    return bool(detect_secret_patterns(text))


def redact_mapping(payload: Mapping[str, Any], *, depth: int = 0) -> dict[str, Any]:
    """Recursively redact a mapping: sensitive keys are replaced, all strings are pattern-scanned."""
    if depth > 12:  # pragma: no cover - defensive against pathological nesting
        return {"_truncated": REDACTED}
    output: dict[str, Any] = {}
    for key, value in payload.items():
        if is_sensitive_key(str(key)):
            output[str(key)] = REDACTED
            continue
        output[str(key)] = redact_value(value, depth=depth + 1)
    return output


def redact_value(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact any JSON-compatible value."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return redact_mapping(value, depth=depth)
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_value(item, depth=depth + 1) for item in value]
    return value


def scan_for_secrets(strings: Iterable[str]) -> dict[str, list[str]]:
    """Map pattern name -> example *locations* is impossible here, so return counts by name.

    Used by the security tests and CI gate: any non-empty result fails the build.
    """
    hits: dict[str, list[str]] = {}
    for index, text in enumerate(strings):
        for name in detect_secret_patterns(text):
            hits.setdefault(name, []).append(f"item#{index}")
    return hits
