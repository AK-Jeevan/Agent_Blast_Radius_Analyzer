"""Data corpus loader: fragments -> registries -> scenario-resolved :class:`AnalysisInput`.

Everything the analyzer consumes is loaded and **validated** here, so failures are loud and early:

* unknown ids are an error, never a silent skip;
* duplicate ids across files are an error (stable ids are load-bearing for evidence);
* scenario expectations referencing ids that do not exist are an error, which catches typos in the
  evaluation ground truth before they can be mistaken for an analyzer bug.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import AliasChoices, BaseModel, ValidationError

from app.config import DATA_DIR
from app.schemas.analysis import AnalysisInput
from app.schemas.common import ActionClass, RunMode
from app.schemas.entities import (
    Agent,
    Blocker,
    Credential,
    Environment,
    Identity,
    InstructionDoc,
    NetworkEdge,
    Permission,
    Resource,
    Tool,
)
from app.schemas.scenario import Scenario
from app.schemas.tolerance import (
    SCHEMA_VERSION,
    is_direct_enum_value,
    resolve_enum_value,
)
from app.utils.ids import stable_sorted


class DataError(RuntimeError):
    """Raised when the data corpus or a scenario is internally inconsistent."""


#: directory -> (model class, registry attribute name)
COLLECTIONS: dict[str, tuple[type[BaseModel], str]] = {
    "environments": (Environment, "environments"),
    "identities": (Identity, "identities"),
    "agents": (Agent, "agents"),
    "tools": (Tool, "tools"),
    "credentials": (Credential, "credentials"),
    "resources": (Resource, "resources"),
    "permissions": (Permission, "permissions"),
    "network": (NetworkEdge, "network"),
    "blockers": (Blocker, "blockers"),
    "instructions": (InstructionDoc, "instructions"),
}

T = TypeVar("T", bound=BaseModel)


def _extract_list(payload: Any, path: Path) -> list[dict[str, Any]]:
    """Accept either a bare JSON list or an object containing exactly one list value."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        lists = [value for value in payload.values() if isinstance(value, list)]
        if len(lists) == 1:
            return lists[0]
        raise DataError(
            f"{path}: expected exactly one list value in the JSON object, found {len(lists)}"
        )
    raise DataError(f"{path}: expected a JSON list or object, found {type(payload).__name__}")


@dataclass
class DataRegistry:
    """All loadable fragments, indexed by id, plus any compatibility warnings from loading."""

    environments: dict[str, Environment] = field(default_factory=dict)
    identities: dict[str, Identity] = field(default_factory=dict)
    agents: dict[str, Agent] = field(default_factory=dict)
    tools: dict[str, Tool] = field(default_factory=dict)
    credentials: dict[str, Credential] = field(default_factory=dict)
    resources: dict[str, Resource] = field(default_factory=dict)
    permissions: dict[str, Permission] = field(default_factory=dict)
    network: dict[str, NetworkEdge] = field(default_factory=dict)
    blockers: dict[str, Blocker] = field(default_factory=dict)
    instructions: dict[str, InstructionDoc] = field(default_factory=dict)
    #: Human-readable notes about anything the loader had to tolerate (see app.schemas.tolerance).
    warnings: list[str] = field(default_factory=list)
    #: Schema revision the corpus was written against.
    schema_version: int = SCHEMA_VERSION

    def get(self, attribute: str, entity_id: str) -> Any:
        mapping: dict[str, Any] = getattr(self, attribute)
        if entity_id not in mapping:
            raise DataError(f"unknown {attribute[:-1]} id: {entity_id!r}")
        return mapping[entity_id]

    def select(self, attribute: str, ids: list[str]) -> list[Any]:
        """Resolve a list of ids, preserving the order the scenario asked for."""
        return [self.get(attribute, entity_id) for entity_id in ids]

    def counts(self) -> dict[str, int]:
        return {
            name: len(getattr(self, name))
            for name in (
                "environments",
                "identities",
                "agents",
                "tools",
                "credentials",
                "resources",
                "permissions",
                "network",
                "blockers",
                "instructions",
            )
        }


def wire_field_names(model: type[BaseModel]) -> set[str]:
    """Every key a producer may legitimately use for this model.

    Includes field *names* **and** aliases, because a wire key may be either: ``NetworkEdge`` is
    written as ``from`` in the corpus and held as ``from_id`` in Python, and treating the alias as
    "unknown" would produce a false compatibility warning on every network edge.
    """
    names: set[str] = set(model.model_fields)
    for declared in model.model_fields.values():
        for alias in (declared.alias, declared.validation_alias, declared.serialization_alias):
            if isinstance(alias, str):
                names.add(alias)
            elif isinstance(alias, AliasChoices):
                # AliasChoices iterates over its `choices`, not over the object itself. The previous
                # code did `for choice in alias`, which on a real AliasChoices raises TypeError; it
                # only ever ran because pydantic models in this project use plain string aliases, so
                # the branch was dead. A model with a choice-based alias -- exactly the kind a lenient
                # parser is meant to tolerate -- would have crashed the loader at import time.
                names.update(choice for choice in alias.choices if isinstance(choice, str))
    return names


def load_json_fragments(
    path: Path,
    model: type[T],
    *,
    strict: bool = False,
    warnings: list[str] | None = None,
) -> dict[str, T]:
    """Load one JSON file into ``id -> model``, rejecting duplicate ids.

    In tolerant mode the loader reports what it did not understand (unknown fields, unknown enum
    values, a newer ``schema_version``) instead of failing, so a producer on a newer schema does not
    take the analyzer down. In strict mode the same findings are errors, which is what CI uses to
    catch schema drift in a pull request.
    """
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = _extract_list(payload, path)
    result: dict[str, T] = {}
    known_fields = wire_field_names(model)
    for raw in items:
        if not isinstance(raw, dict) or "id" not in raw:
            raise DataError(f"{path}: every fragment needs an 'id' field")
        _note_compatibility(path, raw, model, known_fields, strict, warnings)
        try:
            entity = model.model_validate(raw)
        except ValidationError as error:
            raise DataError(f"{path}: {entity_error_message(error, model)}") from error
        # `T` is bound to BaseModel, which has no `id`; every entity model in this project does. The
        # framework models in the corpus are checked for a stable `id` in the schema tests, so reading
        # it through a narrow protocol is the honest expression of the requirement rather than an
        # untyped getattr that would silently produce "<model>" for a model that lacks one.
        entity_id = str(getattr(entity, "id", ""))
        if entity_id in result:
            raise DataError(f"{path}: duplicate id {entity_id!r}")
        result[entity_id] = entity
    return result


def _note_compatibility(
    path: Path,
    raw: dict[str, Any],
    model: type[BaseModel],
    known_fields: set[str],
    strict: bool,
    warnings: list[str] | None,
) -> None:
    """Record (or reject) the compatibility signals present in one raw fragment."""

    def report(message: str) -> None:
        if strict:
            raise DataError(f"{path}: {message}")
        if warnings is not None:
            warnings.append(f"{path.name}: {message}")

    unknown_fields = sorted(set(raw) - known_fields)
    if unknown_fields:
        report(f"ignored unknown field(s) {unknown_fields} on {raw.get('id')!r}")
    declared_version = raw.get("schema_version")
    if isinstance(declared_version, int) and declared_version > SCHEMA_VERSION:
        report(
            f"{raw.get('id')!r} declares schema_version {declared_version} > supported "
            f"{SCHEMA_VERSION}; unknown fields were ignored"
        )
    for key, value in raw.items():
        annotation = model.model_fields.get(key)
        if annotation is None or not isinstance(value, str):
            continue
        enum_cls = _enum_from_annotation(annotation.annotation)
        if enum_cls is None or is_direct_enum_value(enum_cls, value):
            continue
        resolved = resolve_enum_value(enum_cls, value)
        if resolved is None:
            report(f"unrecognised {enum_cls.__name__} value {value!r} on {raw.get('id')!r}.{key}")
        else:
            report(
                f"interpreted {enum_cls.__name__} {value!r} as {resolved.value!r} "
                f"on {raw.get('id')!r}.{key}"
            )


def _enum_from_annotation(annotation: Any) -> type[Enum] | None:
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return annotation
    return None


def entity_error_message(error: ValidationError, model: type[BaseModel]) -> str:
    """Turn a Pydantic error into something a human can act on.

    For the action taxonomy in particular, the useful message is the list of values we *do*
    understand, because that is what the producer has to choose from.
    """
    parts: list[str] = []
    for detail in error.errors():
        location = ".".join(str(item) for item in detail.get("loc", ()))
        kind = detail.get("type", "invalid")
        message = detail.get("msg", "")
        if kind.startswith("enum") or "valid" in kind:
            known = sorted(member.value for member in (ActionClass if "action" in location else ()))
            if known:
                message = f"{message}; known actions: {known}"
        parts.append(f"{location or '<root>'}: {message}")
    return f"could not parse {model.__name__} -> " + "; ".join(parts)


def load_registry(data_dir: Path | None = None, *, strict: bool = False) -> DataRegistry:
    """Load the whole corpus.

    ``strict=True`` turns tolerated drift (unknown fields, unknown enum values, a newer
    ``schema_version``) into errors, which is how CI detects schema drift early.
    """
    root = Path(data_dir) if data_dir is not None else DATA_DIR
    registry = DataRegistry()
    for directory, (model, attribute) in COLLECTIONS.items():
        collection_dir = root / directory
        if not collection_dir.is_dir():
            continue
        merged: dict[str, Any] = {}
        for path in stable_sorted(collection_dir.glob("*.json"), key=lambda item: item.name):
            loaded = load_json_fragments(path, model, strict=strict, warnings=registry.warnings)
            duplicates = set(loaded) & set(merged)
            if duplicates:
                raise DataError(
                    f"{path}: duplicate ids also defined elsewhere: {sorted(duplicates)}"
                )
            merged.update(loaded)
        setattr(registry, attribute, merged)
    if not registry.tools or not registry.resources:
        raise DataError(f"{root}: corpus looks incomplete (tools/resources missing)")
    return registry


def load_scenario(path: Path) -> Scenario:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise DataError(f"{path}: scenario must be a YAML mapping")
    return Scenario.model_validate(payload)


def load_scenarios(directory: Path) -> list[Scenario]:
    """Load every scenario file, sorted by path so ordering is deterministic."""
    scenarios = [
        load_scenario(path)
        for path in stable_sorted(Path(directory).glob("*.y*ml"), key=lambda p: p.name)
    ]
    seen: set[str] = set()
    for scenario in scenarios:
        if scenario.id in seen:
            raise DataError(f"duplicate scenario id: {scenario.id}")
        seen.add(scenario.id)
    return scenarios


def _apply_overrides(model: T, overrides: dict[str, Any], path: str) -> T:
    """Apply scenario-local field overrides and re-validate the entity."""
    payload = model.model_dump(by_alias=False)
    unknown = set(overrides) - set(payload)
    if unknown:
        raise DataError(f"{path}: override targets unknown fields: {sorted(unknown)}")
    payload.update(overrides)
    return type(model).model_validate(payload)


def build_analysis_input(
    registry: DataRegistry,
    scenario: Scenario,
    *,
    run_mode: RunMode = RunMode.A_DETERMINISTIC,
) -> AnalysisInput:
    """Resolve one scenario into a fully validated :class:`AnalysisInput`."""
    agent = registry.get("agents", scenario.agent)
    environment = (
        registry.get("environments", scenario.environment) if scenario.environment else None
    )
    identity_id = scenario.identity or agent.identity
    identity = registry.get("identities", identity_id)

    instruction_ids = scenario.instructions or ([agent.instructions] if agent.instructions else [])
    instructions = registry.select("instructions", [i for i in instruction_ids if i])

    collections: dict[str, list[Any]] = {
        "tools": registry.select("tools", scenario.tools),
        "credentials": registry.select("credentials", scenario.credentials),
        "resources": registry.select("resources", scenario.resources),
        "permissions": registry.select("permissions", scenario.permissions),
        "network": registry.select("network", scenario.network),
        "blockers": registry.select("blockers", scenario.blockers),
    }

    for entity_id, overrides in scenario.overrides.items():
        applied = False
        for items in collections.values():
            for index, item in enumerate(items):
                if item.id == entity_id:
                    items[index] = _apply_overrides(item, overrides, f"{scenario.id}:{entity_id}")
                    applied = True
        if not applied:
            raise DataError(f"{scenario.id}: override for {entity_id!r} matches nothing in scope")

    validate_scenario_references(registry, scenario, collections)

    return AnalysisInput(
        agent=agent,
        environment=environment,
        identity=identity,
        instructions=instructions,
        tools=collections["tools"],
        credentials=collections["credentials"],
        resources=collections["resources"],
        permissions=collections["permissions"],
        network=collections["network"],
        blockers=collections["blockers"],
        scenario_id=scenario.id,
        run_mode=run_mode,
    )


def validate_scenario_references(
    registry: DataRegistry,
    scenario: Scenario,
    collections: dict[str, list[Any]],
) -> None:
    """Fail fast when the scenario's ground truth references entities that cannot exist.

    Positive expectations must reference entities that are actually in scope; negative
    expectations may legitimately reference entities *outside* the scenario (that is the whole point
    of a false-positive guard), but they must still exist in the corpus so typos are caught.
    """
    in_scope = {item.id for items in collections.values() for item in items}
    known = in_scope | set(registry.identities) | set(registry.tools) | set(registry.credentials)
    problems: list[str] = []
    for expectation in scenario.expectations.must_find_capabilities:
        if expectation.target not in in_scope:
            problems.append(f"must_find target not in scope: {expectation.target}")
        for via in expectation.via:
            # `via` may name an identity (the principal behind a credential) which is referenced by
            # the scenario rather than duplicated into it.
            if via not in known:
                problems.append(f"must_find via entity unknown: {via}")
    for expectation in scenario.expectations.must_not_find_capabilities:
        if expectation.target not in registry.resources:
            problems.append(f"must_not_find target unknown to the corpus: {expectation.target}")
    if problems:
        raise DataError(
            f"{scenario.id}: inconsistent expectations -> " + "; ".join(sorted(set(problems)))
        )


def scenario_expectation_summary(scenario: Scenario) -> dict[str, Any]:
    """Compact summary used by the evaluation harness and the API's scenario listing."""
    return {
        "id": scenario.id,
        "title": scenario.title,
        "difficulty": scenario.difficulty,
        "tags": list(scenario.tags),
        "required_findings": scenario.expectations.required_findings,
        "required_absences": scenario.expectations.required_absences,
        "baseline_misses": list(scenario.expectations.expected_baseline_misses),
        "max_severity": (
            scenario.expectations.max_severity.value if scenario.expectations.max_severity else None
        ),
    }
