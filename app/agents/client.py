"""LLM clients for the agentic plane.

Two implementations, one interface:

* :class:`NvidiaClient` -- the real client for the NVIDIA API (OpenAI-compatible) running a
  GLM Flash model. Used when ``NVIDIA_API_KEY`` is configured.
* :class:`ScriptedLLM`   -- a deterministic stand-in that answers the *same* prompts with the
  heuristics a careful analyst would apply, so the pipeline, the verifier, the budgets, and the
  tests all run identically without a network call or an API key.

Both go through :class:`app.agents.verifier.ClaimVerifier` afterwards, so nothing the client says
can become a fact. The stand-in exists so the *architecture* is testable; it is never presented as a
substitute for a real model in the evaluation report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.config import Settings, get_settings


@dataclass(frozen=True)
class LLMResponse:
    """One model response, normalised into strict JSON plus usage counters."""

    payload: dict[str, Any]
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = "scripted"
    cached: bool = False

    @property
    def estimated_cost_usd(self) -> float:
        # Deliberately conservative and clearly labelled: no invented pricing is asserted anywhere.
        return round((self.input_tokens + self.output_tokens) / 1_000_000 * 0.30, 6)


class LLMClient(Protocol):
    """The narrow interface the agentic plane depends on."""

    name: str

    def complete(self, *, system: str, user: str, schema_hint: str) -> LLMResponse: ...

    @property
    def available(self) -> bool: ...


@dataclass
class UsageLedger:
    """Token and call accounting, surfaced in the report's ``metrics`` block."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    history: list[dict[str, Any]] = field(default_factory=list)

    def record(self, response: LLMResponse, *, label: str) -> None:
        self.calls += 1
        self.input_tokens += response.input_tokens
        self.output_tokens += response.output_tokens
        self.cost_usd = round(self.cost_usd + response.estimated_cost_usd, 6)
        self.history.append(
            {
                "label": label,
                "model": response.model,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "cached": response.cached,
            }
        )


class NvidiaClient:
    """OpenAI-compatible client for the NVIDIA API (GLM Flash)."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.name = f"nvidia:{self.settings.nvidia_model}"
        self._client: Any | None = None

    @property
    def available(self) -> bool:
        return bool(self.settings.nvidia_api_key)

    def _ensure_client(self) -> Any:
        if self._client is None:
            from openai import OpenAI  # imported lazily so the module works without the SDK

            self._client = OpenAI(
                api_key=self.settings.nvidia_api_key,
                base_url=self.settings.nvidia_base_url,
                timeout=self.settings.llm_timeout_seconds,
                max_retries=0,
            )
        return self._client

    def complete(self, *, system: str, user: str, schema_hint: str) -> LLMResponse:
        """One chat completion. Never raises: transport failures come back as an error payload.

        The caller decides how to react, which keeps a model outage from failing an analysis that
        the deterministic plane can still perform.
        """
        if not self.available:
            return LLMResponse(payload={"error": "no_api_key"}, model=self.settings.nvidia_model)
        try:
            client = self._ensure_client()
            completion = client.chat.completions.create(
                model=self.settings.nvidia_model,
                temperature=0.0,
                max_tokens=1200,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system},
                    {
                        "role": "user",
                        "content": f"{user}\n\nRespond with JSON only. Shape:\n{schema_hint}",
                    },
                ],
            )
        except Exception as error:  # transport/provider errors are data, not crashes
            return LLMResponse(
                payload={"error": f"{type(error).__name__}: {error}"},
                model=self.settings.nvidia_model,
            )
        choice = completion.choices[0]
        raw = choice.message.content or "{}"
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"error": "unparseable_json", "raw": raw[:500]}
        usage = getattr(completion, "usage", None)
        return LLMResponse(
            payload=payload,
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage, "completion_tokens", 0) or 0,
            model=self.settings.nvidia_model,
        )


class ScriptedLLM:
    """Deterministic stand-in for the real model.

    It answers the same three prompts using the same inputs a careful analyst would read, so the
    pipeline, verifier, budgets, and tests exercise the production code path with no network call.
    Its outputs are *proposals* like any model's, and the verifier is what decides their fate -- which
    is exactly the point of the architecture. The evaluation report always records which client
    produced a run, so a stand-in run can never be mistaken for a model run.
    """

    name = "scripted:heuristic"

    def __init__(self) -> None:
        self.usage = UsageLedger()

    @property
    def available(self) -> bool:
        return True

    def complete(self, *, system: str, user: str, schema_hint: str) -> LLMResponse:
        from app.agents.heuristics import answer_prompt  # local import avoids a cycle

        payload = answer_prompt(system=system, user=user, schema_hint=schema_hint)
        response = LLMResponse(
            payload=payload,
            input_tokens=max(1, len(user) // 4),
            output_tokens=max(1, len(str(payload)) // 4),
            model=self.name,
            cached=True,
        )
        self.usage.record(response, label=schema_hint[:40])
        return response


def build_client(settings: Settings | None = None, *, prefer_real: bool | None = None) -> LLMClient:
    """Return the real NVIDIA client when a key is configured, otherwise the scripted stand-in.

    ``prefer_real`` (env ``LLM_PREFER_REAL``) lets the test suite and the evaluation harness pin the
    scripted client so runs are reproducible and free, while the API and the UI use the real model.
    """
    settings = settings or get_settings()
    use_real = settings.llm_prefer_real if prefer_real is None else prefer_real
    if use_real and settings.llm_enabled:
        return NvidiaClient(settings)
    return ScriptedLLM()


__all__ = [
    "LLMClient",
    "LLMResponse",
    "NvidiaClient",
    "ScriptedLLM",
    "UsageLedger",
    "build_client",
]
