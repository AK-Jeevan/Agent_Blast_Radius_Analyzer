"""Security helpers: secret masking and trust-channel quarantine.

* :mod:`app.security.masking` -- redaction of secret-looking material, detection patterns.
* :mod:`app.security.trust`   -- structural separation of untrusted text from instructions.
* :mod:`app.security.injection` -- injection *signals* (never used as enforcement by themselves).
"""

from __future__ import annotations

from app.security.masking import (
    REDACTED,
    contains_secret,
    detect_secret_patterns,
    is_sensitive_key,
    redact_mapping,
    redact_text,
    redact_value,
    scan_for_secrets,
)
from app.security.trust import (
    DataEnvelope,
    DataPayload,
    quarantine_payload,
    render_data_block,
    render_instruction_block,
)

__all__ = [
    "REDACTED",
    "DataEnvelope",
    "DataPayload",
    "contains_secret",
    "detect_secret_patterns",
    "is_sensitive_key",
    "quarantine_payload",
    "redact_mapping",
    "redact_text",
    "redact_value",
    "render_data_block",
    "render_instruction_block",
    "scan_for_secrets",
]
