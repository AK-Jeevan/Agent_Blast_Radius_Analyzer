"""Credential analysis: obtainability, validity, scope, and the escalation they imply.

A credential is modelled as *metadata only* (``secret_ref`` locator, never a value). Two questions
are answered here:

1. **Can the agent obtain it?** either it is already present in the agent's environment, or a tool in
   scope can read it (``discoverable_via``). The second case is an escalation, not a detail: it means
   the credential's authority is reachable even when it was never granted to the agent.
2. **Is it usable?** expiry in the past makes the authority merely *declared*; unknown expiry caps
   the resulting capability at ``probable`` and must be reported as an uncertainty.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from app.schemas.analysis import AnalysisInput
from app.schemas.common import Source
from app.schemas.entities import Credential


def parse_timestamp(raw: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp; ``None``/unparseable means UNKNOWN, never 'valid'."""
    if not raw:
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


@dataclass(frozen=True)
class CredentialStatus:
    """Everything the engine needs to know about one credential in one scenario."""

    credential: Credential
    present: bool
    indirect: bool
    obtained_via: tuple[str, ...]
    expiry_state: str  # "valid" | "expired" | "unknown"
    usable: bool
    scope_environments: tuple[str, ...]
    assumed_identity: str | None
    note: str = ""

    @property
    def id(self) -> str:
        return self.credential.id

    @property
    def expires_at(self) -> datetime | None:
        return parse_timestamp(self.credential.expires_at)


def analyse_credential(
    analysis_input: AnalysisInput,
    credential: Credential,
    *,
    now: datetime | None = None,
) -> CredentialStatus:
    """Determine whether one credential is obtainable and usable in this scenario."""
    now = now or datetime.now(UTC)
    tool_ids = {tool.id for tool in analysis_input.tools}
    via_tools = tuple(sorted(set(credential.discoverable_via) & tool_ids))
    declared_present = credential.id in set(analysis_input.agent.credentials_present)
    # A credential is *present* when the runtime supplies it, which is true either because the agent
    # declares it or because no tool in scope can read it (so it did not arrive through discovery).
    # When a tool in scope can read it and the agent does not declare it, the only way to reach it is
    # that discovery step -- which is an escalation, tracked separately.
    present = declared_present or not via_tools
    indirect = bool(via_tools)

    expiry = parse_timestamp(credential.expires_at)
    if expiry is None:
        expiry_state = "unknown"
    elif expiry <= now:
        expiry_state = "expired"
    else:
        expiry_state = "valid"

    usable = (present or indirect) and expiry_state != "expired"
    note = ", ".join(
        filter(
            None,
            [
                "present in agent environment" if present else None,
                f"discoverable via {', '.join(via_tools)}" if indirect else None,
                f"expiry {expiry_state}" if expiry_state != "valid" else None,
            ],
        )
    )
    return CredentialStatus(
        credential=credential,
        present=present,
        indirect=indirect,
        obtained_via=via_tools,
        expiry_state=expiry_state,
        usable=usable,
        scope_environments=tuple(sorted(set(credential.scope))),
        assumed_identity=credential.assumed_identity,
        note=note,
    )


def analyse_credentials(
    analysis_input: AnalysisInput, *, now: datetime | None = None
) -> list[CredentialStatus]:
    """Analyse every credential in scope, ordered deterministically by id."""
    reference = now or datetime.now(UTC)
    return [
        analyse_credential(analysis_input, credential, now=reference)
        for credential in sorted(analysis_input.credentials, key=lambda item: item.id)
    ]


def scope_conflicts_with_resource(status: CredentialStatus, environment: str | None) -> bool:
    """True when a credential's scope excludes the target environment (a reportable conflict)."""
    if not environment or not status.scope_environments:
        return False
    return environment not in status.scope_environments


def credential_source(credential: Credential) -> Source:
    """Provenance for evidence about a credential (its own, so trust labels survive)."""
    return credential.source
