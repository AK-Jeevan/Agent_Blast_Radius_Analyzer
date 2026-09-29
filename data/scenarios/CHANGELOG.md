# Scenario changelog

Expectations are part of the evaluation's ground truth, so changing one is a recorded event.
Any edit to a scenario's `expectations` block requires an entry here stating **why**, so the
evaluation cannot be quietly re-tuned to match the analyzer.

| Date | Scenario | Change | Reason |
|---|---|---|---|
| 2026-09-28 | all | initial authoring (12 scenarios, S1–S12 + the S10 recoverable/irreversible pair) | Phase 1 baseline; each scenario carries a mandatory `must_not_find_capabilities` control |
| 2026-09-28 | scenario-06 | `permissions` changed from `pol-ci-read-svc` to `pol-dev-read-shared` | `pol-ci-read-svc` does not exist in the corpus; the scenario must reference real policies |
| 2026-09-28 | scenario-08 | `expected_baseline_misses` set to `[]` pending measurement | Whether the state-gated HTTP capability is reachable by the deterministic baseline is an empirical question. The ablation run (Phase 11) fills this in from measurement rather than from hope. |
| 2026-09-28 | 04, 05, 06, 07, 08, 11, 12 | `expected_contradictions` populated where it had been left `[]` | **Ground-truth gap, not a retune.** Wiring the §5 families into the harness exposed that contradiction precision was scoring 0.125, and every "unexpected" code turned out to be a correct detection that the ground truth had simply never declared. Each is corroborated by the scenario's *own* text, independently of the analyzer: scenario-07 is titled "environment-boundary-violation", is tagged `declared_intent_violation`, and states in its notes that the capability "crosses a boundary that the configuration claims is closed" — yet declared no contradiction expected. scenario-11 and scenario-12 exist specifically to prove that `MISLEADING_METADATA` is detected ("poisoned tool metadata ... must not create capabilities"; "MCP server claims full production access; structured policy says no"). scenario-04's own `must_not_find` note explains why the `res-prod-db` DELETE is not actionable ("no route to it is in scope here"), which is precisely `AUTHORITY_UNREACHABLE`. Leaving these as `[]` penalised the analyzer for being right and made the metric unable to distinguish a true detection from a false alarm — the exact opposite of what the family exists to measure. No `must_find`/`must_not_find` entry was changed, and no severity bound was relaxed. |
| 2026-09-28 | scenario-06 | `via` extended to name both composing tools (`tool-read-file`, `tool-http-request`) | The scenario's own note describes the chain as "reading the workspace environment file yields the CI deployment token; querying the CI pipeline reveals the production deployment endpoint" — two tools, but `via` listed only the first. Because the composed-capability family is derived from expectations naming two or more tools, the corpus's own existence proof had no composed expectation to score against, and composition recall reported "no ground truth" everywhere. The engine's finding is unchanged; only the ground truth now describes the chain the scenario already described in prose. |

## Rules

1. `must_find_capabilities` and `must_not_find_capabilities` are the ground truth and are derived from
   the fragments by hand, then cross-checked against what the fragments can possibly support.
2. `expected_baseline_misses` is a *prediction* about mode A. If mode A turns out to find a predicted
   miss, the prediction is corrected and the fact is reported in the ablation results (it is evidence
   that less of the system needs an LLM).
3. Expected severities use the documented tables in `docs/ANALYSIS_ENGINE_SPEC.md` §4 and §6. If an
   expectation disagrees with the engine, one of the two is wrong: the mismatch is investigated, not
   tuned away.
