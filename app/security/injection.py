"""Prompt-injection *signalling* (not enforcement).

Detection here exists to produce reportable evidence — an ``InjectionAttempt`` finding attributed to
a specific input source — and to strengthen the "rejected claim" signal. It is explicitly **not** the
enforcement mechanism: enforcement is the structural quarantine in :mod:`app.security.trust` plus the
deterministic verifier. A pattern we fail to recognise therefore cannot grant the model authority,
because the model never had authority over facts in the first place.
"""

from __future__ import annotations

import re

from app.schemas.analysis import InjectionAttempt

#: (pattern name, regex, is_instruction_override)
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b"
            r"(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instruction|rule|prompt|guideline|policy)"
        ),
        True,
    ),
    (
        "role_reassignment",
        re.compile(r"(?i)\byou are now\b|\bact as\b[^.\n]{0,20}\b(admin|root|unrestricted)\b"),
        True,
    ),
    (
        "credential_exfiltration",
        re.compile(
            r"(?i)\b(expose|reveal|print|dump|send|leak|exfiltrate)\b[^.\n]{0,30}\b"
            r"(credential|secret|token|password|api[ _-]?key|env(?:ironment)? var)"
        ),
        True,
    ),
    (
        "scope_escalation",
        re.compile(
            r"(?i)\b(assume|grant|treat)\b[^.\n]{0,30}\b"
            r"(full|admin|administrator|unrestricted|all)\b[^.\n]{0,20}\b(access|permission|right)"
        ),
        True,
    ),
    (
        "unbounded_work_loop",
        re.compile(
            r"(?i)\b(keep|continue|repeat)\b[^.\n]{0,30}\b(checking|scanning|analyz\w*|searching)\b"
            r"[^.\n]{0,30}\b(every|all|until)\b"
        ),
        True,
    ),
    (
        "command_execution_request",
        re.compile(
            r"(?i)\b(run|execute|invoke)\b[^.\n]{0,30}"
            r"(?:[\w-]*shell|[\w-]*command|[\w-]*script|payload|curl|wget|bash)\b"
        ),
        True,
    ),
    (
        "false_authority_claim",
        re.compile(
            r"(?i)\b(administrator|admin|root|superuser)\b[^.\n]{0,30}\b(access|privilege|permission|mode)\b"
        ),
        False,
    ),
)

#: How aggressively a pattern can be treated as evidence of a deliberate injection attempt.
CONFIDENT_PATTERNS: frozenset[str] = frozenset(
    {
        "instruction_override",
        "role_reassignment",
        "credential_exfiltration",
        "scope_escalation",
        "command_execution_request",
    }
)


def scan_text(source_ref: str, text: str, *, max_excerpt: int = 160) -> list[InjectionAttempt]:
    """Return injection-attempt findings for one piece of untrusted text.

    ``excerpt`` is a short, quoted sample of the *offending* text so a human can adjudicate it. It is
    always presented as data, and it is masked for secret-looking content by the caller's pipeline.
    """
    if not text:
        return []
    attempts: list[InjectionAttempt] = []
    for name, pattern, _is_override in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            attempts.append(
                InjectionAttempt(
                    source_ref=source_ref,
                    pattern=name,
                    handling="quarantined_as_data",
                    excerpt=match.group(0)[:max_excerpt],
                )
            )
    return attempts


def scan_untrusted_texts(items: list[tuple[str, str]]) -> list[InjectionAttempt]:
    """Scan many ``(source_ref, text)`` pairs, de-duplicating identical (source, pattern) hits."""
    seen: set[tuple[str, str]] = set()
    attempts: list[InjectionAttempt] = []
    for source_ref, text in items:
        for attempt in scan_text(source_ref, text):
            key = (attempt.source_ref, attempt.pattern)
            if key not in seen:
                seen.add(key)
                attempts.append(attempt)
    return attempts


def is_instruction_override(pattern_name: str) -> bool:
    """True when a detected pattern suggests a deliberate attempt to redirect the analyzer."""
    return pattern_name in CONFIDENT_PATTERNS
