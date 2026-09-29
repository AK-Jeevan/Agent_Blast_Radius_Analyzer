"""Gradio demo UI (Phase 13).

The UI calls the *service layer* directly, so it runs standalone without the API process; both paths
end at :func:`app.services.orchestrator.analyse`, so the demo and the API cannot drift apart.

Design rule visible here: the UI **always shows the baseline next to the agentic result**, including
rejected claims and unmet uncertainties. Hiding those would make the product look more confident
than it is.

    python gradio_app/app.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

import gradio as gr

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import DATA_DIR, get_settings  # noqa: E402
from app.schemas.common import RunMode  # noqa: E402
from app.services.loader import (  # noqa: E402
    build_analysis_input,
    load_registry,
    load_scenarios,
)
from app.services.orchestrator import analyse  # noqa: E402
from gradio_app import views  # noqa: E402

REGISTRY = load_registry()
SCENARIOS = {scenario.id: scenario for scenario in load_scenarios(DATA_DIR / "scenarios")}

#: The scenario the interface opens on, or ``None`` when the corpus is empty. The dropdown and the
#: expectations panel both read the default from here so they cannot disagree on first render: the
#: panel used to be built from ``None`` and said "select a scenario" while the dropdown was already
#: showing one. ``next(..., None)`` also means an empty corpus renders an empty dropdown instead of
#: raising ``StopIteration`` while the interface is being constructed.
DEFAULT_SCENARIO = next(iter(SCENARIOS.values()), None)

MODE_HELP = {
    RunMode.A_DETERMINISTIC.value: "facts only (IAM, credentials, reachability, action semantics)",
    RunMode.B_INTERPRET.value: "+ LLM tool-semantics interpretation",
    RunMode.C_AGENTIC.value: "+ tool composition across tools",
    RunMode.D_FULL.value: "+ state-dependent analysis and counterfactuals",
}


def scenario_choices() -> list[tuple[str, str]]:
    """(label, id) pairs so the dropdown shows a human title."""
    return [(f"{scenario.id} — {scenario.title}", scenario.id) for scenario in SCENARIOS.values()]


def run_analysis(
    scenario_id: str,
    run_mode: str,
    with_counterfactuals: bool,
    prefer_real_llm: bool,
) -> tuple[str, list[list[Any]], list[list[Any]], list[list[Any]], str, str, str, str]:
    """Run one analysis and return every view the interface renders."""
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        return ("Pick a scenario.", [], [], [], "", "{}", "*unknown scenario*", "[]")
    settings = get_settings().model_copy(update={"llm_prefer_real": prefer_real_llm})
    analysis_input = build_analysis_input(REGISTRY, scenario, run_mode=RunMode(run_mode))
    outcome = analyse(
        analysis_input,
        run_mode=RunMode(run_mode),
        settings=settings,
        with_counterfactuals=with_counterfactuals,
    )
    report = outcome.report
    return (
        views.overview_markdown(scenario, report, outcome.notes),
        views.capability_rows(report),
        views.finding_rows(report),
        views.counterfactual_rows(report),
        report.report_text or "",
        json.dumps(views.chain_view(report, scenario), indent=2),
        views.honesty_markdown(report),
        json.dumps(views.trajectory_rows(report), indent=2),
    )


def build_ui() -> gr.Blocks:
    """Assemble the demo interface.

    Gradio 6 moved presentation parameters such as ``theme`` from the ``Blocks`` constructor to
    ``launch()``, so the theme is applied by the entry point below rather than here. This function
    deliberately takes no theme argument: accepting one and ignoring it advertised a knob that did
    nothing.
    """
    with gr.Blocks(title="Agent Blast-Radius Analyzer") as ui:
        gr.Markdown(
            "# Agent Blast-Radius Analyzer\n"
            "**What can this agent actually affect, how did it get that capability, and what would "
            "reduce it?** Deterministic analysis plus agentic reasoning whose every claim is "
            "verified before it is reported."
        )
        with gr.Row():
            with gr.Column(scale=2):
                scenario = gr.Dropdown(
                    choices=scenario_choices(),
                    label="Scenario",
                    value=DEFAULT_SCENARIO.id if DEFAULT_SCENARIO is not None else None,
                )
                mode = gr.Radio(
                    choices=[item.value for item in RunMode],
                    value=RunMode.D_FULL.value,
                    label="Run mode",
                    info=" | ".join(f"**{key}**: {value}" for key, value in MODE_HELP.items()),
                )
                with gr.Row():
                    counterfactuals = gr.Checkbox(value=True, label="Counterfactuals")
                    real_llm = gr.Checkbox(
                        value=False,
                        label="Use real NVIDIA GLM Flash",
                        info="Off = deterministic scripted stand-in (reproducible, offline, free)",
                    )
                analyze = gr.Button("Analyze blast radius", variant="primary")
            with gr.Column(scale=1):
                expectations = gr.Markdown(views.expectations_markdown(DEFAULT_SCENARIO))
        overview = gr.Markdown()
        with gr.Tab("Capabilities"):
            capabilities = gr.Dataframe(
                headers=[
                    "action",
                    "target",
                    "environment",
                    "severity",
                    "status",
                    "confidence",
                    "state_depth",
                    "discovered_by",
                    "path",
                ],
                wrap=True,
                interactive=False,
            )
        with gr.Tab("Findings"):
            findings = gr.Dataframe(
                headers=[
                    "severity",
                    "finding",
                    "recoverability",
                    "confidence",
                    "facts",
                    "uncertainties",
                ],
                wrap=True,
                interactive=False,
            )
        with gr.Tab("Counterfactuals"):
            gr.Markdown(
                "**Analysis only** — nothing is applied to any environment. Each row is a control "
                "that provably shrinks the blast radius, measured by re-running the deterministic "
                "engine on the modified facts."
            )
            counterfactual_table = gr.Dataframe(
                headers=["control", "severity", "capabilities removed", "narrative"],
                wrap=True,
                interactive=False,
            )
        with gr.Tab("Report"):
            report_text = gr.Code(language=None, lines=40, interactive=False)
        with gr.Tab("Graph"):
            graph_json = gr.Code(language="json", interactive=False)
        with gr.Tab("Honesty"):
            honesty = gr.Markdown()
            trajectory = gr.Code(label="Agentic trajectory", language="json", interactive=False)

        analyze.click(
            fn=run_analysis,
            inputs=[scenario, mode, counterfactuals, real_llm],
            outputs=[
                overview,
                capabilities,
                findings,
                counterfactual_table,
                report_text,
                graph_json,
                honesty,
                trajectory,
            ],
        )
        scenario.change(
            fn=lambda chosen: views.expectations_markdown(SCENARIOS.get(chosen)),
            inputs=scenario,
            outputs=expectations,
        )
    # gr.Blocks is built through a context manager and gradio ships no type information for it, so the
    # value arrives as Any. The cast states the real contract instead of letting the annotation degrade
    # to Any for every caller of build_ui().
    return cast(gr.Blocks, ui)


# Bound to ``demo`` rather than ``app``: this module already imports the ``app`` *package* at the
# top, so rebinding that name to a Blocks instance would break any later ``from app.x import y``
# here -- an import that reads fine but resolves to the interface object.
demo = build_ui()


if __name__ == "__main__":  # pragma: no cover - manual entry point
    settings = get_settings()
    demo.launch(
        server_name=settings.gradio_host,
        server_port=settings.gradio_port,
        theme=gr.themes.Soft(),
        show_error=True,
    )
