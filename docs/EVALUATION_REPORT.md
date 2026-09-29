# Evaluation report

Generated 2026-09-29 08:47 UTC by `python scripts/build_eval_report.py` (13 scenarios, scripted client, offline and reproducible).

## How to read this

Recall is over capability triples `(action, target, environment)`. A **false positive** is a
capability a scenario explicitly forbids; a finding that is merely *unlisted* is not counted as
one, because scenarios do not enumerate every real capability. `errors` counts scenarios that
failed to run, and an errored scenario scores 0 recall — never 1.

## Ablation (the independent variable is the run mode)

| mode | recall | precision | F1 | false-positive rate | severity violations | errors |
|---|---|---|---|---|---|---|
| A_deterministic | 0.944 | 1.000 | 0.971 | 0.000 | 0 | 0 |
| B_interpret | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0 |
| C_agentic | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0 |
| D_full | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0 |

## What the agentic layer actually added

- Deterministic baseline recall: **0.944**; full system recall: **1.000**.
- False positives introduced by the agentic layer: **0.0** (no scenario regressed).

The gap the agentic layer closes is the *composition* one: a development agent that holds no
production grant, no deploy tool, and no direct route to the production endpoint, yet can read
a workspace file, obtain the CI deployment token, and drive the pipeline API — a production
deploy. The deterministic baseline cannot see it (no structured `DISCOVERS` edge points at
production); the agentic layer proposes the chain, and the verifier accepts it only because
obtainability, reachability, and authorization all check out.

## Per-scenario results (full system)

| scenario | difficulty | recall | FP | max severity | missing |
|---|---|---|---|---|---|
| scenario-01-staging-only | easy | 1.00 | 0 | MEDIUM | - |
| scenario-02-production-read | easy | 1.00 | 0 | MEDIUM | - |
| scenario-03-production-write | medium | 1.00 | 0 | HIGH | - |
| scenario-04-destructive-tool | medium | 1.00 | 0 | HIGH | - |
| scenario-05-credential-discovery | medium | 1.00 | 0 | MEDIUM | - |
| scenario-06-tool-composition | hard | 1.00 | 0 | MEDIUM | - |
| scenario-07-environment-boundary-violation | medium | 1.00 | 0 | HIGH | - |
| scenario-08-stateful-capability | hard | 1.00 | 0 | MEDIUM | - |
| scenario-09-network-isolation | medium | 1.00 | 0 | INFO | - |
| scenario-10-delete-recoverable | medium | 1.00 | 0 | HIGH | - |
| scenario-10b-delete-irreversible | hard | 1.00 | 0 | CRITICAL | - |
| scenario-11-adversarial-metadata | adversarial | 1.00 | 0 | LOW | - |
| scenario-12-mcp-metadata-untrusted | adversarial | 1.00 | 0 | MEDIUM | - |

## Model availability (honest reporting)

- `NVIDIA_API_KEY` configured in this environment: **True**.
- Configured model: `z-ai/glm-5.3-flash` — confirmed present in the live NVIDIA
  `/v1/models` catalog, where the GLM Flash id is `z-ai/glm-5.3-flash`.
- **The `/v1/chat/completions` endpoint did not respond from this machine** during the build
  (the connection succeeds, the read times out), so **no number in this report comes from a
  real model call**. Every sweep above ran through the deterministic scripted client, which
  exercises the identical prompts, pipeline, and verifier.
- When the endpoint is unavailable the run **degrades explicitly**: the model error appears in
  the trajectory as `DEGRADE` steps, `MODEL_UNAVAILABLE_FALLBACK` is added to
  `metrics.caps_hit`, and the analysis still completes. Verified end to end.
- To run against the real model where the network allows:
  `python scripts/run_eval.py --mode D_full --real-llm`.

## Kill-test status

**Not yet executed.** The gate (`docs/EVALUATION_PLAN.md` §6) requires 50+ *unseen* scenarios
with the code frozen. The corpus currently holds 13 curated scenarios, 11 of which were used
while building the engine. The measured evidence so far supports the agentic layer on **one**
axis (composition) and shows no regression on the others — which is not yet the three-axis
improvement the gate demands. Stated here rather than implied away.

## What we could not verify

- Behaviour of the real model on adversarial or ambiguous inputs (no live call completed).
- Multi-turn behaviour beyond a single investigation trajectory.
- Behaviour with real IAM exports; the corpus is hand-authored to stay diagnosable.

