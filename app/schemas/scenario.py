"""Scenario schema: the evaluation contract (docs/EVALUATION_PLAN.md §2 + §3).

A scenario composes data fragments by id and declares machine-checkable expectations, including
mandatory **negative** expectations. The loader rejects a scenario without a negative control, and
re-derives every expectation with the deterministic engine so ground truth cannot drift into
"whatever the system happened to output".
"""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import ActionClass, Severity
from app.schemas.tolerance import input_config


class ExpectedCapability(BaseModel):
    model_config = input_config()

    action: ActionClass
    target: str
    environment: str | None = None
    min_severity: Severity | None = None
    max_severity: Severity | None = None
    via: list[str] = Field(
        default_factory=list, description="entity ids expected somewhere on the capability path"
    )
    min_state_depth: int = 0
    is_negative: bool = False
    note: str | None = None

    def matches(self, action: str, target: str, environment: str | None) -> bool:
        if self.action.value != action or self.target != target:
            return False
        if self.environment is None:
            return True
        return self.environment == environment

    @property
    def label(self) -> str:
        suffix = f"@{self.environment}" if self.environment else ""
        return f"{self.action.value}->{self.target}{suffix}"


class ScenarioExpectations(BaseModel):
    """Positive and negative expectations. Negative ones are mandatory."""

    model_config = input_config()

    must_find_capabilities: list[ExpectedCapability] = Field(default_factory=list)
    must_not_find_capabilities: list[ExpectedCapability] = Field(default_factory=list)
    expected_uncertainties: list[str] = Field(default_factory=list)
    expected_contradictions: list[str] = Field(default_factory=list)
    expected_baseline_misses: list[str] = Field(default_factory=list)
    max_severity: Severity | None = None
    min_severity: Severity | None = None
    notes: str | None = None

    @property
    def required_findings(self) -> int:
        return len(self.must_find_capabilities)

    @property
    def required_absences(self) -> int:
        return len(self.must_not_find_capabilities)


class Scenario(BaseModel):
    """One evaluation scenario: a selected subset of the environment corpus + expectations."""

    model_config = input_config()

    id: str
    title: str
    difficulty: str = "medium"  # easy | medium | hard | adversarial
    tags: list[str] = Field(default_factory=list)
    environment: str | None = None
    agent: str
    identity: str | None = None
    instructions: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    credentials: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    network: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    overrides: dict[str, dict[str, object]] = Field(
        default_factory=dict,
        description="scenario-local field overrides, e.g. {'net-agent-to-prod-api': {'reachable': true}}",
    )
    expectations: ScenarioExpectations = Field(default_factory=ScenarioExpectations)

    @model_validator(mode="after")
    def _validate_negative_control(self) -> Scenario:
        """A scenario without a negative expectation is invalid (docs/EVALUATION_PLAN.md §3.2)."""
        if not self.expectations.must_not_find_capabilities:
            raise ValueError(
                f"scenario {self.id}: must_not_find_capabilities is empty; "
                "every scenario needs a false-positive guard"
            )
        if not self.expectations.must_find_capabilities:
            raise ValueError(f"scenario {self.id}: must_find_capabilities is empty")
        overlap = {item.label for item in self.expectations.must_find_capabilities} & {
            item.label for item in self.expectations.must_not_find_capabilities
        }
        if overlap:
            raise ValueError(
                f"scenario {self.id}: expectation appears in both lists: {sorted(overlap)}"
            )
        return self
