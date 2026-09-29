# Phase 0 — Formal Problem Definition (Agent Blast-Radius Analyzer)

**Status:** Draft for review — no implementation may begin until this document is agreed.
**Version:** 0.1
**Scope of this document:** defines the problem, the vocabulary, the formal data model, the
detonating assumptions we intend to *falsify*, the simulated environment, the deterministic
baseline, the first evaluation scenarios, and the minimal MVP architecture.

> Everything downstream (Phases 1–18) is a direct implementation of something written here.
> If a design decision is not traceable to a section of this document, it is not yet justified.

---

## 0. One-sentence problem statement

> Given a *declared* configuration of an AI agent (identity, instructions, tools, credentials,
> network position, resources, permissions), compute the **set of real-world state changes the
> agent could actually cause if its reasoning, instructions, or inputs were compromised**, together
> with the evidence for each claimed capability, the confidence in it, its severity, and its
> recoverability.

**Non-goals (explicitly out of scope — see §44 of the master prompt):** generic AI governance,
IAM scanning, vulnerability scanning, prompt-injection *detection as a product*, MCP gateways,
agent observability dashboards, chatbots, LLM wrappers, static permission visualization, and any
form of automated remediation. This is an **analysis-only** system.

**Safety invariant (non-negotiable):** the analyzer is read-only with respect to the analyzed
environment. It never deploys, mutates IAM, rotates credentials, deletes data, or executes
arbitrary shell/cloud commands. All "action" reasoning is *simulation over a graph*, never
execution against a live target.

---

## 1. What "blast radius" means for an AI agent

For a *static* system (a VM, a service account, a human user) blast radius is roughly
"permissions × reachability". For an agent that gap explodes because the *composition* of
capabilities, the *order* in which they are used, and the *information* accumulated mid-session
create capabilities that exist in no single place in the configuration.

**Definition 1.1 (Blast radius).**
The blast radius of an agent `A` in environment configuration `C` is the set of *effectful
outcomes* — ordered triples `(action, target resource, environment)` — that `A` can potentially
cause, each annotated with:

| Facet | Meaning |
|---|---|
| `provenance` | which tool/credential/identity/path enables it |
| `verification` | confirmed / probable / possible / unverified / contradicted |
| `confidence` | numeric, backed by an evidence count (never a substitute for evidence) |
| `severity` | impact class derived from action semantics × target criticality × environment |
| `recoverability` | recoverable / difficult / potentially irreversible (+ backup/rollback facts) |
| `dependency_impact` | downstream resources affected transitively |

So blast radius is **not** "list of permissions". It is a **set of (action, target) pairs with
provenance, evidence, confidence, severity and recovery semantics attached**.

**Definition 1.2 (Effective blast radius).**
The subset of the blast radius that survives *all* of the following filters, which must each be
evaluated independently and never collapsed:

```
1. identity authenticates          (does A hold a usable identity at the target?)
2. credential is valid + unexpired (scope, issuer, audience, lifetime)
3. network path exists             (can the call physically/routeably be made?)
4. authorization permits the verb  (IAM / policy / ACL decision on (principal, action, resource))
5. tool exposes the action         (semantics of the tool surface: can it express this verb?)
6. schema allows the parameters    (input schema is powerful enough to name the target)
7. precondition satisfiable        (does the tool need prior state: a path, a token, an ID?)
8. non-blocking control absent     (approval gate, dry-run, rate limit, guardrail)
```

`Effective blast radius ⊆ Blast radius` always. The gap between them *is the product*: it is
exactly where false alarms and false confidence come from.

**Definition 1.3 (Capability).** A capability is a *typed, grounded* statement of the form

```
Capability = (action_class, target_resource_class, environment, precondition_set, provenance_set)
```

Capabilities — not permissions — are the unit of analysis. A permission is a *fact about
authorization*; a capability is a *conclusion about achievable effect*.

---

## 2. The five-layer ladder (and why collapsing it is the core failure mode)

```
L0  DECLARED AUTHORITY     what config *claims*              FACT source: policy/docs/annotations
L1  REACHABLE AUTHORITY    what the agent can physically     FACTS: credentials, network, endpoints
                           reach and authenticate to
L2  EFFECTIVE CAPABILITY   what it can actually *do*,         INFERENCE: composition + semantics
                           incl. multi-tool / multi-step
L3  POTENTIAL IMPACT       what happens if that capability    INFERENCE: state, backups, dependents
                           is used at the worst moment
L4  EFFECTIVE BLAST RADIUS L2 ∩ L3 filtered by blockers,      CONCLUSION: severity + recovery
                           verified, with evidence attached
```

| Layer | Example | Typical error if conflated |
|---|---|---|
| L0 Declared | IAM policy says `s3:DeleteObject` on `prod-backups` | Reported as "can delete backups" — **false positive** |
| L1 Reachable | Token exists but is scoped to `dev-*` / expired / VPC-sandboxed | Ignored — **false negative** |
| L2 Effective | `read_env` → `read_secret` → `deploy` = production deploy | Missed entirely by permission scanners |
| L3 Impact | Deploy breaks prod; rollback exists → recoverable | "Critical" claimed for a reversible action |
| L4 Blast Radius | Production *deployment* reachable, database **not** | Uncalibrated severity, no evidence trail |

**Design rule (R1):** the report must always show L0 and L1 *separately*, and must show the
*difference*. Where they disagree, the system reports **contradiction** (§41 of the master prompt)
rather than silently choosing one.

---

## 3. Why traditional IAM/permission analysis is insufficient for agentic systems

A permission-scanner assumes the actor is a *human or service that executes intent faithfully*.
Agentic systems violate that assumption on six axes:

1. **Instruction ≠ intent.** The agent's own system prompt can be overridden by untrusted content
   it reads (indirect prompt injection). The *config* is not the attacker's set of moves; the
   agent's *reachable inputs* are. Therefore declared intent contributes *nothing* to blast radius
   reduction — only blockers (approval gates, dry-run, least privilege) do.
2. **Capability lives in composition.** `read_file` + `read_env` + `http_post` is a deploy pipeline.
   No single permission grants deploy; the *composition* does. IAM analysis is monotone in
   individual grants and blind to composition. → §6 of master prompt.
3. **State accumulates.** A session carries facts forward: an endpoint discovered at step 1 makes
   a credential usable at step 4. Blast radius is a function of the *trajectory*, not the initial
   config. → §7.
4. **Semantics are natural-language.** Tool names/descriptions are text. `run_sql(string)` may be
   read-only by convention and destructive in fact; `deploy(env)` may or may not accept `"prod"`.
   Schema *shape* is deterministic; schema *meaning* is not. This is the legitimate home of the LLM.
5. **Credentials are payloads, not just permissions.** An agent with `read_file` and no cloud
   permission can still read `./.env` and thereby *acquire* cloud permission. Credential
   *accessibility* is a capability in itself and must be modelled as an escalation edge.
6. **Reachability ≠ authorization ≠ actionability.** Network reachable ≠ authenticated ≠ authorized
   ≠ expressible through an available tool's schema. Collapsing these four produces both panic and
   complacency.

**Consequence:** the system must compute a **capability closure over a heterogeneous graph**
(identity, credential, tool, resource, network, environment, dependency), then apply
**action semantics**, then apply **blockers**, then attach **evidence and confidence**.

---

## 4. Why tool composition and session state matter (worked example)

Config facts only:

```
tools:      read_file, read_env, http_request, run_sql
credentials: [dev-token]   (scope: development)
network:     ["agent" -> "internet"], ["agent" -> "dev-db"]
blockers:    none
```

Naive conclusion: "Development only. LOW."

Composition + state reasoning:

```
State0: {tools, dev-token}
 step1 read_file("./.env")            -> State1 += {DEPLOY_TOKEN: "svc-ci-deploy"}     [credential discovery]
 step2 read_env("CI_*")               -> State1 += {CI_API="https://ci.internal"}     [resource discovery]
 step3 http_request(CI_API, DEPLOY_TOKEN) -> State2 += {deploy pipeline "prod-web"}   [network + authz]
 step4 http_request(pipeline, action=deploy, ref="main")
                                      -> State3 += {PRODUCTION DEPLOYMENT CAPABILITY}
```

Effective blast radius: **production deployment** (HIGH, rollback available), reached with **zero
production IAM grants to the agent identity**. A permission-only tool reports LOW. This is the
existence proof for the whole product, and it is *scenario 6* in §9 below.

## 5. Action semantics (why `delete_database` ≠ `read_database_schema`)

Authorization asks *"is verb V allowed on resource R?"*. Impact asks *"what does doing V to R
cost, and can it be undone?"*. Different questions, different evidence.

**Action taxonomy (closed vocabulary — MVP):**

| Class | Verbs | Effect direction | Typical severity | Recovery |
|---|---|---|---|---|
| `READ` | read, get, list, describe, query_select, export | information out | LOW–MEDIUM (data exposure) | recoverable, but disclosure itself is irreversible |
| `WRITE` | write, put, update, patch, modify, upsert, migrate | state mutation | MEDIUM–HIGH | recoverable if versioned/backed up |
| `CREATE` | create, provision, register, upload | new artifact | LOW–MEDIUM | recoverable |
| `DELETE` | delete, drop, truncate, purge, remove, terminate | destruction | HIGH–CRITICAL | depends on backups; often irreversible |
| `EXECUTE` | execute, run, invoke, eval, shell, ssh, spawn | arbitrary code / lateral movement | HIGH–CRITICAL | context dependent |
| `DEPLOY` | deploy, release, publish, promote, apply, rollout | changes a live system | HIGH | rollback present ⇒ downgraded |
| `ROLLBACK` | rollback, revert, restore | corrective | LOW (often beneficial) | n/a |
| `ROTATE` | rotate, revoke, rename | identity/credential control | MEDIUM–HIGH (can lock out operators) | difficult |
| `GRANT`/`REVOKE` | grant, revoke, attach/detach policy, set-role | **privilege escalation** | CRITICAL (escalation ⇒ recompute closure) | recoverable, but the chain reopens |
| `EXFILTRATE` | *derived* (see below) | data leaves the boundary | HIGH–CRITICAL | disclosure is irrecoverable |
| `DESTROY` | *derived* (see below) | permanent loss | CRITICAL | potentially irreversible |

Two **derived** (composite) classes matter most, because composition is precisely what permission
scanning cannot see:

```
EXFILTRATE := READ(data-class resource) ∧ (network egress to a non-boundary sink) ∧ ¬DLP blocker
DESTROY    := DELETE(target) ∧ ¬∃(backup of target) ∧ ¬∃(restore|rollback path)
```

**Design rule (R3):** severity is `f(action_class, target_criticality, environment,
recoverability)` — never a constant. `DELETE` on `dev-scratch` and `DELETE` on `prod-db` must not
yield the same finding. Environment multipliers (dev 0.4 / test 0.5 / staging 0.75 / prod 1.0 by
default, overridable per scenario) and criticality tags are **data**, not code.

---

## 6. Recovery characteristics (why "destructive" ≠ "severity")

Every destructive finding carries a recovery profile:

```
RecoveryProfile = {
  recoverability: "recoverable" | "difficult" | "potentially_irreversible" | "unknown",
  mechanisms:     [rollback | backup | snapshot | versioning | replica | supervisor | none],
  latest_recovery_point:  <age or None>,       # only if the scenario supplies it
  mean_time_to_recover:   <estimate or None>,  # only if the scenario supplies it
  evidence:       [evidence_id, ...]           # facts that prove the mechanism exists
}
```

Invariant table (used as unit-test expectations in §9, scenario S10):

| Action | Recovery profile | Result |
|---|---|---|
| `restart_service` | mechanism: supervisor/orchestrator | LOW |
| `rollback_deployment` | mechanism: previous artifact retained | LOW (corrective) |
| `DELETE prod-db` | mechanism: snapshot @ T-1h | HIGH, recoverable |
| `DELETE prod-db` **+** `DELETE prod-backups` | mechanism: none | CRITICAL, potentially irreversible |

**Design rule (R4):** absent recovery facts ⇒ `recoverability: UNKNOWN`, and severity is **capped
at what the facts justify**. The system must never assert "irreversible" *or* "safe" from silence.
No invented business-impact numbers, no invented MTTR, no invented $ figures.

---

## 7. Deterministic vs agentic — the division of labour

The central engineering claim of this project. **The LLM is never the authority on any fact that
can be computed.** It may only *propose* propositions that the deterministic layer verifies.

### 7.1 Deterministic plane (LLM forbidden) — *Facts*

| Concern | Method |
|---|---|
| Graph build/traverse/path enumeration | NetworkX; bounded DFS/BFS, visited-set, depth cap, cycle-safe |
| Credential scope/expiry/audience | Set + interval algebra on parsed structures |
| Authorization decisions | Policy evaluator over structured `permissions[]`: verb match, resource glob/ARN match, **explicit deny wins**, default deny |
| Network reachability | Reachability closure over `network[]` edges (+ `internet_egress` flags); reachable ≠ authorized |
| Environment boundaries | Environment-label comparison; cross-env edge detection |
| Blocker evaluation | Approval gate / dry-run / rate limit / allow-list / masking presence |
| Secret masking | Deterministic redaction at the parser boundary; secret values never enter state, prompts, logs, or the report |
| Severity, recoverability, scoring | Fixed formulas over classification tables (§5, §6) |
| Evidence assembly + contradiction detection | Set algebra on typed evidence objects (subject, predicate, polarity, source) |
| Prompt-injection *neutralization* | Structural: untrusted text is JSON-encoded into **data** fields, never concatenated into instruction positions; injection patterns flagged as *signal*, never obeyed |
| Budgets, loop detection, termination | Counters; hypothesis hashing; step/tool/token/time caps; duplicate suppression |

### 7.2 Agentic plane (NVIDIA API + GLM Flash) — *Semantics*

| Task | Why semantics are genuinely required | Verification obligation |
|---|---|---|
| Tool-semantics interpretation | `run_query` may hide DDL; descriptions are prose | Evidence span required; marked `interpreted`, never `confirmed` |
| Hidden/implicit capability discovery | A "sync helper" may be arbitrary write | Must name the graph edge it presumes |
| Candidate capability-chain generation | Propose which 3–5 tool sequences deserve deterministic checking | Reported only after deterministic edge validation |
| Tool composition reasoning | Emergent capability from primitives | Every hop must resolve to a real edge, else downgrade to HYPOTHESIS |
| Ambiguity resolution | Description vs. schema conflict | Must emit a contradiction record, not a verdict |
| Session/state reasoning | Preconditions and ordering ("needs a repo path first") | Recursive deterministic precondition check on the proposed trajectory |
| Counterfactual narrative | Explaining *why* removing an edge shrinks the radius | Numeric deltas come from re-running the deterministic engine |
| Explanation faithfulness | Rendering verified evidence as prose | Each sentence must cite ≥1 evidence id (automatically checked) |

### 7.3 Anti-hallucination boundary (interface contract)

```
LLM strict-JSON proposal
        |
        v
   ClaimVerifier  --> ACCEPTED   (confidence capped by evidence count & type)
        |         --> DOWNGRADED (e.g. "confirmed" -> "possible")
        |         --> REJECTED   (unknown entity id / missing cited evidence / invents a fact)
        v
  report["agent_rejected_claims"]     <- hallucinations are displayed as hallucinations
```

Verifier rules (all deterministic): referenced entity ids must exist; every cited evidence id must
exist *and* actually support the claim; no resource/credential/permission/network fact may
originate from the LLM; `verification_status` may never be raised above `possible` by the LLM.

Every rejected claim is also an **injection signal**: if untrusted text provoked a rejected claim,
that is recorded as an `injection_attempt` finding attributed to that input source.

## 8. Formal data model

See **[`DATA_MODEL.md`](./DATA_MODEL.md)**. Summary of the commitment:

| Layer | Entities | Where they come from |
|---|---|---|
| L0 declared authority | `Permission`, `Identity.trusted_for`, prose claims | parsed structured input (trusted) or untrusted metadata (data-only) |
| L1 reachable authority | `Credential`, `NetworkEdge`, `Blocker` | parsed structured input |
| L2 effective capability | `Tool` (+ action semantics, preconditions), `Capability` | **computed** |
| L3 impact | `Resource` (+ `RecoveryProfile`, `dependents`), `Environment` | parsed structured input |
| Evidence / reasoning | `Evidence` (FACT/INFERENCE/HYPOTHESIS/CONTRADICTION), `InvestigationState` | produced by the engine |

Two invariants are baked into the schema itself:

1. **`None` means UNKNOWN** everywhere — never false, never allowed. Silence must surface as
   uncertainty, never as safety.
2. **Trust is a field, not an assumption.** Input text carries `source.trusted`; untrusted text is
   data-only and can never occupy an instruction position in an LLM prompt.

## 9. Initial simulated environment

See **[`SIMULATED_ENVIRONMENT.md`](./SIMULATED_ENVIRONMENT.md)**: 4 environments (dev/staging/prod +
shared), 13 resources with recovery profiles, 13 tools (including two adversarial and one ambiguous
pair), 6 credentials (metadata only — no values anywhere), 6 blockers, and dependency chains that
make transitive reasoning testable. Every scenario is a YAML composition of these fragments with
machine-checkable positive **and** negative expectations.

## 10. First 10 evaluation scenarios, baseline, and the proof-of-value protocol

See **[`EVALUATION_PLAN.md`](./EVALUATION_PLAN.md)**. In one line: 10 scenarios covering
staging-only, prod-read, prod-write, destructive, credential discovery, tool composition,
environment-boundary violation, stateful capability, network isolation, and
recoverable-vs-irreversible — each with expected capabilities, expected severity band, expected
uncertainties, and an explicit `expected_baseline_misses` prediction.

The baseline is defined as: **IAM/permission evaluation + credential scope + network reachability +
environment labels + graph traversal + action taxonomy — with no semantic inference of any kind.**
The agentic layer must beat it on *composition, state, ambiguity, and counterfactual* axes, or it
gets removed from the architecture (kill test, §10.6 of the evaluation plan).

## 11. MVP architecture

See **[`MVP_ARCHITECTURE.md`](./MVP_ARCHITECTURE.md)** for the module-by-module plan, the
deterministic/agentic boundary in code, and the phase-by-phase build order mapped onto this
repository's actual structure.

## 12. Decision log & open questions

### Decisions taken in Phase 0

| # | Decision | Rationale |
|---|---|---|
| D1 | Heterogeneous single `MultiDiGraph`, not separate stores | Parallel edge types must stay distinguishable ("reachable but not authorized") |
| D2 | Capabilities, not permissions, are the output unit | Permission lists are not blast radius |
| D3 | `None = UNKNOWN` everywhere; severity capped by facts | Prevents confident nonsense; forces honesty about missing input |
| D4 | LLM output is *proposals*, always verified by a deterministic `ClaimVerifier` | Anti-hallucination is architectural, not prompt-based |
| D5 | Untrusted text is structurally quarantined (data-only fields) | Prompt injection cannot be fixed by instructions; it is fixed by channels |
| D6 | `state_depth` recorded on every capability | Makes "stateful capability discovery" measurable rather than claimed |
| D7 | Blockers are first-class entities | Counterfactuals and "declared ≠ effective" both need them |
| D8 | Baseline must be built *before* the LLM layer and reused to score it | Otherwise the agentic claim is unfalsifiable |

### Open questions for you (answers change implementation, not design)

| # | Question | Default I will use if you don't object |
|---|---|---|
| Q1 | Repo hygiene: this folder is nested inside the `DPO_Conncise_Chatbot` git repo (`C:\Users\akjee\Documents\AI`). Should I `git init` a **separate** repository inside `AI Blast Radius Analyzer`, or keep committing into the parent repo? | `git init` a separate repo here + ask you to add it as a new GitHub repo before Phase 15 CI work |
| Q2 | NVIDIA API key availability + exact model id (e.g. `zai-org/glm-4.5-flash` vs an NGC `glm-*-flash` id)? Until it exists, Phases 6+ run against a recorded-fixture stub so nothing else blocks. | Build the LLM layer behind an interface with a `FakeLLM` that replays fixtures; wire the real client when the key exists |
| Q3 | Scope for the first milestone: stop after Phase 5 (deterministic + evidence engine + report) or push through Phase 13 (API + UI) in one go? | Deliver Phase 1→5 fully tested first, then API, then UI |
| Q4 | Do you want a `Makefile`-style task runner (`scripts/` + `make`) or plain PowerShell scripts? | Plain PowerShell scripts in `scripts/` (Windows-first, works everywhere) |



