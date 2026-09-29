# Agent Blast-Radius Analyzer

**What can an AI agent *actually* affect — and how do we know?**

This project analyzes an AI agent's environment (identity, tools, credentials, permissions, network,
resources, blockers) and computes its **effective blast radius**: the real-world state changes the
agent could cause if it were confused, manipulated, or compromised — including capabilities that
emerge only from *combining* tools, *accumulating* information across a session, or *crossing*
environment boundaries.

> **Status: implemented and tested through the MVP (Phases 1–15).**
> 56 tests pass · ruff clean · 13-scenario corpus · measured A/B/C/D ablation.
> Two honest caveats live in [`docs/EVALUATION_REPORT.md`](docs/EVALUATION_REPORT.md): the real
> NVIDIA model could not be reached from this machine, and the 50+ unseen-scenario kill test has not
> been run yet.

---

## Measured result (the whole point of the project)

Capability recall over the scenario corpus, deterministic baseline vs. agentic system:

| mode | recall | precision | F1 | false-positive rate |
|---|---|---|---|---|
| `A_deterministic` (no LLM) | **0.944** | 1.000 | 0.971 | 0.000 |
| `B_interpret` (+ semantics) | **1.000** | 1.000 | 1.000 | 0.000 |
| `C_agentic` (+ composition) | **1.000** | 1.000 | 1.000 | 0.000 |
| `D_full` (+ stateful) | **1.000** | 1.000 | 1.000 | 0.000 |

The single capability the deterministic baseline **cannot** find is the composed one:

```
read_file("./.env")           -> CI deploy token       (credential discovery)
http_request(CI, token)       -> production endpoint    (endpoint discovery, prose only)
http_request(endpoint, deploy)-> PRODUCTION DEPLOYMENT   (authorized as ident-deploy-svc)
```

The agent holds **no production grant, no deploy tool, and no direct route**. The baseline misses it
because no structured `DISCOVERS` edge points at production. The agentic layer proposes the chain;
the deterministic verifier accepts it *only* because obtainability, reachability, and authorization
all check out — and it is reported as `possible`, never `confirmed`. **No scenario gained a false
positive** to get there.

Reproduce it:

```powershell
.\Agent3\Scripts\python.exe scripts\build_eval_report.py     # regenerates docs/EVALUATION_REPORT.md
```

---

## The problem in one page

Permission scanners answer *"what is the agent allowed to do?"*. That is not the question that
matters. An agent with no production grants can still reach production by:

```
read_file("./.env")     -> deploy token           (credential discovery)
read_env("CI_*")        -> CI endpoint            (resource discovery)
http_request(CI, token) -> pipeline               (network + authentication)
http_request(pipeline, action=deploy)             (authorization + action semantics)
                                                  = PRODUCTION DEPLOYMENT, zero prod IAM grants
```

Individually each tool is harmless. Together they are a deployment pipeline. Blast radius is a
property of **composition, state, and semantics** — not of the permission list.

## The five layers we refuse to collapse

| Layer | Meaning | Source |
|---|---|---|
| **L0 Declared authority** | what config *claims* | parsed policies, prose metadata |
| **L1 Reachable authority** | what the agent can physically reach and authenticate to | credentials, network, endpoints |
| **L2 Effective capability** | what it can actually *do*, incl. multi-tool / multi-step paths | **computed** |
| **L3 Potential impact** | what happens if it does, incl. recoverability and dependents | computed from facts |
| **L4 Effective blast radius** | L2 ∩ L3, filtered by blockers, verified, evidence-backed | **the product** |

Every report shows L0 and L1 **separately** with the delta between them, because the gap between
declared and effective is where both false alarms and real danger hide.

## Design commitments

1. **Deterministic where possible, agentic only where semantics are genuinely required.** Graph
   traversal, IAM evaluation, credential scope, reachability, severity and recoverability are
   deterministic. The LLM (NVIDIA API + GLM Flash) *proposes*; a deterministic verifier disposes.
2. **Evidence or it didn't happen.** Every HIGH/CRITICAL finding needs ≥2 FACT evidence items, or it
   is downgraded and the shortfall is reported.
3. **Unknown ≠ safe.** `None` means UNKNOWN everywhere. Missing input produces uncertainty, never a
   clean bill of health.
4. **Read-only and analysis-only.** The analyzer never mutates the environment it analyzes, never
   executes commands derived from input, and never handles secret values (only locators).
5. **Untrusted text is data, never instructions.** Prompt injection is handled structurally, by
   channel separation — not by asking a model politely to ignore it.
6. **The baseline is built first and used to judge the agentic layer.** If the LLM does not measurably
   improve composition / state / ambiguity / counterfactual analysis, it is removed (kill test).

## Repository layout

```text
app/
  analyzers/     DETERMINISTIC plane: graph, authz, reachability, credentials,
                 closure, scoring, evidence, blast_radius, report, counterfactual
  agents/        AGENTIC plane: client (NVIDIA GLM Flash + scripted stand-in),
                 prompts (channel separation), verifier, pipeline
  graph/         heterogeneous MultiDiGraph builder, typed views, bounded paths
  security/      masking, trust quarantine, injection signals
  evaluation/    scenario runner, metrics, ablation harness
  api/           FastAPI routes + request/response schemas
  services/      data loader, orchestrator (run modes), run store
  schemas/       Pydantic v2 models == docs/DATA_MODEL.md, field for field
  main.py        app factory
data/            simulated environment: 4 environments, 17 resources, 16 tools
                 (2 adversarial), 7 credentials, 13 policies, 25 network edges,
                 6 controls, 6 agents, 6 instruction docs
  scenarios/     13 scenarios with machine-checked positive AND negative expectations
gradio_app/      demo UI (assembles views from the same service layer as the API)
tests/           unit · integration · security
scripts/         setup_env.ps1, run_eval.py, build_eval_report.py
docs/            Phase 0 design docs + generated EVALUATION_REPORT.md
.github/         tests.yml · security.yml · docker.yml
Agent3/          the Python virtual environment (git-ignored)
```

## Documentation index

| Document | Contents |
|---|---|
| [`docs/PHASE_0_PROBLEM_DEFINITION.md`](docs/PHASE_0_PROBLEM_DEFINITION.md) | problem statement, five-layer model, why IAM-only analysis fails, action taxonomy, recovery model, deterministic/agentic split, decision log, open questions |
| [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) | every entity, field, relationship, the graph model, and the capability/output objects |
| [`docs/ANALYSIS_ENGINE_SPEC.md`](docs/ANALYSIS_ENGINE_SPEC.md) | closure algorithm, authorization/credential/network rules, severity + recovery formulas, evidence/confidence/contradiction model, agent state and budgets, counterfactuals, output contract |
| [`docs/SIMULATED_ENVIRONMENT.md`](docs/SIMULATED_ENVIRONMENT.md) | the offline fictional dataset: environments, resources, tools (incl. adversarial ones), credentials, blockers, ground-truth invariants |
| [`docs/EVALUATION_PLAN.md`](docs/EVALUATION_PLAN.md) | the 10 seed scenarios, the 4-version ablation (A/B/C/D), metric definitions, adversarial suite, and the kill test |
| [`docs/MVP_ARCHITECTURE.md`](docs/MVP_ARCHITECTURE.md) | module map, run modes, phase-by-phase build order, non-negotiable implementation constraints |

## Quickstart

```powershell
# From the project root
powershell -ExecutionPolicy Bypass -File .\scripts\setup_env.ps1   # creates/updates .\Agent3
.\Agent3\Scripts\Activate.ps1
python -m pytest                 # 56 tests: unit + integration + security
python -m ruff check app gradio_app tests scripts
python scripts\run_eval.py --mode D_full       # score the whole corpus
python scripts\run_eval.py --ablation          # the A/B/C/D table
python scripts\run_eval.py --scenario scenario-06 --print-report   # one report, in full

# Serve it
uvicorn app.main:app --reload --port 8000       # API (docs at /docs)
python gradio_app\app.py                        # demo UI
```

Request an analysis:

```powershell
curl.exe -X POST http://127.0.0.1:8000/analyze -H "content-type: application/json" `
  -d '{"scenario_id":"scenario-06","run_mode":"D_full","with_counterfactuals":true,"prefer_real_llm":false}'
```

Copy `.env.example` to `.env` before using the LLM layer; `.env` is git-ignored.

> **This machine:** pip is configured with an unreachable NVIDIA extra index
> (`pypi.ngc.nvidia.com`); `setup_env.ps1` neutralizes it for the install process only.
> `NVIDIA_API_KEY` is present, but `/v1/chat/completions` does not answer here, so runs degrade to
> the deterministic stand-in and say so (`MODEL_UNAVAILABLE_FALLBACK`). Use `--real-llm` where the
> endpoint is reachable.

## Using the real model

```powershell
$env:NVIDIA_API_KEY = "nvapi-..."
$env:NVIDIA_MODEL  = "z-ai/glm-5.3-flash"     # confirmed in the live NVIDIA catalog
$env:LLM_PREFER_REAL = "true"
python scripts\run_eval.py --mode D_full --real-llm
```

The agentic layer then calls `z-ai/glm-5.3-flash` through the OpenAI-compatible NVIDIA endpoint.
Whatever it proposes faces the same deterministic verifier: unknown entity ids, missing authorization,
unreachable targets, and invented spans are **rejected and printed** in `agent_rejected_claims`
rather than believed.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Problem definition, data model, engine spec, environment, evaluation plan | complete |
| 1–5 | Corpus + schemas + masking → graph → deterministic analyzer → scoring → evidence | complete |
| 6–10 | NVIDIA client → verifier-gated proposals → composition → stateful → counterfactuals | complete |
| 11–13 | Evaluation harness + ablation → FastAPI → Gradio | complete |
| 14–15 | Docker + compose → GitHub Actions (tests / security / docker) | complete |
| 16–17 | AWS deployment · richer observability (tracing, Prometheus) | not started |
| 18 | Kill test on 50+ unseen scenarios, live-model evaluation, final packaging | **not started** |

## License

MIT. The simulated environment contains no real credentials, endpoints, or customer data.

