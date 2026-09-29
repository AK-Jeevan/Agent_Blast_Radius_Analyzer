"""Run the evaluation harness from the command line.

python scripts/run_eval.py                 # all scenarios, deterministic mode (default)
python scripts/run_eval.py --mode D_full   # one run mode
python scripts/run_eval.py --ablation      # A/B/C/D comparison table
python scripts/run_eval.py --scenario scenario-06-tool-composition
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import DATA_DIR  # noqa: E402
from app.evaluation.runner import ablation, evaluate, run_scenario, write_artifacts  # noqa: E402
from app.schemas.common import RunMode  # noqa: E402
from app.services.loader import load_registry, load_scenarios  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--ablation" in args:
        table = ablation()
        print(json.dumps(table, indent=2, default=str))
        return 0

    mode = RunMode.A_DETERMINISTIC
    if "--mode" in args:
        mode = RunMode(args[args.index("--mode") + 1])

    registry = load_registry()
    scenarios = load_scenarios(DATA_DIR / "scenarios")
    if "--scenario" in args:
        wanted = args[args.index("--scenario") + 1]
        scenarios = [item for item in scenarios if item.id.startswith(wanted)]
        if not scenarios:
            print(f"no scenario matched {wanted!r}")
            return 1

    # The harness defaults to the deterministic scripted client so a sweep is reproducible, free, and
    # offline. `--real-llm` runs the NVIDIA GLM Flash client instead (slower, non-deterministic).
    prefer_real = "--real-llm" in args

    if len(scenarios) == 1 and "--print-report" in args:
        result, report = run_scenario(
            scenarios[0], registry, run_mode=mode, keep_report=True, prefer_real_llm=prefer_real
        )
        print(report.report_text if report is not None else f"run failed: {result.error}")
        return 0

    summary, _reports = evaluate(
        mode, registry=registry, scenarios=scenarios, prefer_real_llm=prefer_real
    )
    target = write_artifacts(summary)
    payload = summary.as_dict()
    payload.pop("scenarios_detail", None)
    print(json.dumps(payload, indent=2, default=str))
    print(f"\nartifacts: {target}")
    for item in summary.results:
        if item.missing or item.unexpected or item.severity_violations:
            print(
                f"  {item.scenario_id}: missing={[m.label for m in item.missing]} "
                f"unexpected={item.unexpected} severity={item.severity_violations}"
            )
    return 0 if summary.errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
