# MVP Architecture (Phase 0 proposal) — Agent Blast-Radius Analyzer

## 0. Principle

The MVP is **one Python package, one process per entry point, one graph, two analysis planes**:

```
                     ┌──────────────────────────────┐
   CLI / tests  ───► │  app/services/orchestrator   │ ───► Report (JSON + text)
   FastAPI      ───► │  (analysis_id, run modes)    │
   Gradio       ───► └───────────┬──────────────────┘
                                 │
        ┌────────────────────────┼─────────────────────────┐
        ▼                        ▼                         ▼
  DETERMINISTIC PLANE      AGENTIC PLANE            EVIDENCE / SCORING
  app/analyzers/*          app/agents/*             app/analyzers/evidence.py
  - parser / loader        - loop.py (bounded)      app/analyzers/scoring.py
  - graph builder          - tools.py (analysis     app/analyzers/report.py
  - authz evaluator          tools the LLM may call)
  - reachability           - prompts (data-only)
  - closure / expansion    - client (NVIDIA API)
  - taxonomy tables        - verifier (rejects bad claims)
                                 │
                                 ▼
                        app/graph/ (networkx views)
```

**Rule R6 (enforced by a test):** no module under `app/analyzers/` may import from `app/agents/`.
The dependency arrow points one way only — agentic code depends on deterministic results, never the
reverse. That single import rule is what makes the ablation study (A/B/C/D) mechanically possible.

## 1. Repository layout (this directory = project root)

```text
AI Blast Radius Analyzer/
├── Agent3/                     # the venv you asked for (never committed)
├── app/
│   ├── main.py                 # FastAPI app factory (Phase 12)
│   ├── config.py               # env-driven settings; no secret literals in code
│   ├── api/                    # routers: analyze, analysis, graph, health, metrics
│   ├── schemas/                # Pydantic v2 models == DATA_MODEL.md, field for field
│   ├── models/                 # internal dataclasses (Evidence, RecoveryProfile, State)
│   ├── services/               # orchestrator, run store, registry, report writer
│   ├── analyzers/              # DETERMINISTIC PLANE (see §0)
│   ├── graph/                  # builder + typed views + path enumeration + hashing
│   ├── agents/                 # AGENTIC PLANE (LLM loop, tools, prompts, verifier)
│   ├── security/               # masking, trust-channel quarantine, injection signals, budgets
│   ├── evaluation/             # scenario loader, runner, metrics, ablation harness
│   └── utils/                  # structlog setup, id/clock/io helpers
├── data/                       # SIMULATED_ENVIRONMENT.md (fragments + scenarios)
├── docs/                       # PHASE_0_*, DATA_MODEL, ANALYSIS_ENGINE_SPEC, EVALUATION_PLAN, ...
├── gradio_app/                 # Phase 13 UI (separate entry point, same service layer)
├── scripts/                    # PowerShell: setup_env, run_api, run_ui, run_eval, lint
├── tests/                      # unit / integration / security / evaluation
├── requirements.txt  .env.example  .gitignore  README.md
├── Dockerfile  docker-compose.yml
└── .github/workflows/          # tests.yml, security.yml, docker.yml (Phase 15)
```

## 2. Run modes — one orchestrator, four configurations

`RunMode` is a parameter of the orchestrator, so the ablation study is a configuration rather than
a rewrite of the system:

| Mode | Contents | Purpose |
|---|---|---|
| `A_deterministic` | closure + authz + reachability + taxonomy only | the baseline; always available, always fast |
| `B_interpret` | A + LLM tool-semantics interpretation (single shot, no loop) | isolates the *semantic* gain |
| `C_agentic` | A + bounded agentic loop with analysis tools | isolates the *search/agent* gain |
| `D_full` | A + loop + composition + state + counterfactual + narrative | the product |

`POST /analyze` accepts `run_mode` (default `D_full`) and always returns the A-result alongside the
requested result, so the UI can literally display *"baseline said X, agentic said Y"*. The project's
honesty about where the LLM helps is a feature, not a caveat.

## 3. Module responsibilities and build order (mapped to the 18 phases)

| Phase | Deliverable | Files | Done-when |
|---|---|---|---|
| 1 | Simulated environment + schemas | `data/**`, `app/schemas/*` | loader round-trips every fragment; secret-value assertion passes; 10 scenarios load |
| 2 | Resource graph | `app/graph/builder.py`, `views.py` | graph built from fragments; expected edge counts per view; parallel edges preserved |
| 3 | Deterministic analyzer | `app/analyzers/{authz,reachability,credentials,environments,closure,taxonomy}.py` | S1–S10 deterministic axes match expectations |
| 4 | Blast-radius calculation | `app/analyzers/{scoring,blast_radius}.py` | severity + recovery invariant tables hold as unit tests |
| 5 | Evidence engine + report | `app/analyzers/{evidence,contradictions,report}.py` | every HIGH/CRITICAL finding carries ≥2 FACT items or is downgraded; text report renders |
| 6 | NVIDIA + GLM Flash client | `app/agents/client.py` (+ `FakeLLM`) | works against recorded fixtures; no secret leaves the process |
| 7 | Agentic loop | `app/agents/{loop,tools}.py`, `agents/prompts/` | loop respects MAX_STEPS/MAX_TOOL_CALLS/timeout; loop detection proven by test |
| 8 | Tool composition | `app/agents/composition.py`, `app/analyzers/composition_check.py` | composed chains reported only after deterministic edge validation |
| 9 | Stateful analysis | `app/agents/state.py`, `app/analyzers/expansion.py` | `state_depth ≥ 1` capabilities found on S6/S8 |
| 10 | Counterfactuals | `app/analyzers/counterfactual.py` | removing an edge provably removes the predicted capability |
| 11 | Evaluation harness | `app/evaluation/*`, `data/scenarios/**` | 50+ scenarios; metrics + ablation from one command |
| 12 | FastAPI | `app/api/*`, `app/main.py` | `/analyze`, `/analysis/{id}`, `/analysis/{id}/report`, `/analysis/{id}/graph`, `/health`, `/metrics` |
| 13 | Gradio | `gradio_app/app.py` | overview, graph, findings, counterfactuals render from a real run |
| 14 | Docker | `Dockerfile`, `docker-compose.yml` | API + UI containers run an analysis end-to-end |
| 15 | CI/CD | `.github/workflows/{tests,security,docker}.yml` | lint → unit → integration → security → evaluation → docker build |
| 16 | AWS | `deploy/` | smallest viable: App Runner **or** ECS Fargate + S3 artifacts (no Kubernetes) |
| 17 | Observability | `app/utils/logging.py`, `/metrics` | structured logs, token usage, trajectory persisted per run |
| 18 | Packaging | `README.md`, `docs/*`, demo | a reader reproduces the evaluation from the README alone |

## 4. Non-negotiable implementation constraints

1. **Read-only analysis.** No module may egress to analyzed targets, mutate analyzed systems, or
   execute shell commands derived from input. A test asserts that `subprocess`/`os.system` appear
   nowhere outside `scripts/`.
2. **Secrets never modeled.** Masking/redaction happens at the parser boundary (Phase 1). A CI test
   greps fixtures, logs, and report snapshots for secret-looking patterns and fails on a hit.
3. **Budgets are configuration, not vibes.** `MAX_AGENT_STEPS`, `MAX_TOOL_CALLS`, `MAX_LLM_CALLS`,
   `TIMEOUT_SECONDS`, `MAX_PATH_LENGTH`, `MAX_STATE_DEPTH` come from the environment with
   conservative defaults, and every run reports which caps were hit (`termination_reason`).
4. **Determinism where it is promised.** Same input ⇒ byte-identical deterministic output (sorted
   collections, content-hash ids). Agentic output is compared against that baseline, never silently
   merged into it.
5. **Channel separation (prompt-injection defence).** Untrusted text is placed in clearly delimited
   *data* fields as JSON; system instructions never interpolate input. The LLM's own instructions
   explicitly state that fenced content is untrusted data. Detection of injection patterns is a
   *signal* for the report, never the enforcement mechanism — enforcement is structural.
6. **UI never hides the baseline.** The Gradio app must show deterministic and agentic results side
   by side, including rejected claims and unmet uncertainties.

## 5. What Phase 1 will produce next (smallest useful increment)

```
data/{environments,identities,agents,tools,credentials,resources,permissions,network,blockers}/*.json
data/scenarios/scenario-01..10-*.yaml
app/schemas/*.py            # Pydantic v2 == DATA_MODEL.md
app/security/masking.py     # redaction + trust-channel helpers
tests/unit/test_schemas.py  # round-trip + None=UNKNOWN + no-secret assertions
scripts/setup_env.ps1       # recreate Agent3 + install requirements.txt
```

Nothing in Phase 1 touches NetworkX or the LLM: it is data + types + the masking boundary, which is
exactly what makes Phase 2 onwards testable.

