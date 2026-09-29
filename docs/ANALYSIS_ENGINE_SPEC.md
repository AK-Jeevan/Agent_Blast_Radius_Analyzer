# Analysis Engine Spec (Phase 0) — deterministic core rules

Companion to `PHASE_0_PROBLEM_DEFINITION.md` §7 and `DATA_MODEL.md`. This is the precise set of
rules the deterministic engine implements in Phases 3–5. Anything not expressible here is either
(a) semantics work for the agentic layer, or (b) out of scope.

## 1. Deterministic closure algorithm (the baseline)

```
INPUT: parsed facts F = (agent, identities, tools, credentials, resources,
                         permissions, network, blockers, environments)

1. BUILD      heterogeneous MultiDiGraph G from F (edges only from structured facts)
2. AUTH       for each (principal, credential, resource) compute authority set:
                  authorized_actions = union over permissions p of
                      p.actions  where p.effect == allow
                                 and matches(p.resources, resource)
                                 and principal_matches(p, credential.assumed_identity)
                  then subtract every explicit deny match                 # deny wins, always
3. CRED       usable_credentials(agent) = { c :
                    c.discoverable_via ∩ agent.tools ≠ ∅                  # obtainable
                 or c is mounted/declared present for the agent
                 and (c.expires_at is None or c.expires_at > now) }       # validity
4. NET        reachable(target)   = exists path in reachability_view with all edges reachable
               authenticated(target) = exists usable credential on a reaching path
               authorized(target)    = actions ≠ ∅ from step 2
               actionable(target,a)  = reachable ∧ authenticated ∧ authorized(a)
                                       ∧ ∃ tool exposing a whose targets match
                                       ∧ tool.preconditions ⊆ satisfiable(state)
5. EXPAND     state growth: repeat until fixpoint (bounded by MAX_STATE_DEPTH):
                  for each tool t with discovery_capability D reachable from agent:
                      add D to state; re-run steps 2–4
                  for each reachable endpoint/resource with DISCOVERS edges: same
6. CAPS       capabilities = { (action, resource, env) : actionable(action, resource, env) }
7. IMPACT     for each capability: severity(base) via §4 table -> adjust for environment
               multiplier, criticality, blockers, recoverability -> severity(final)
8. EVIDENCE   assemble evidence per capability: every hop contributes ≥1 evidence object
9. CONTRADICT detect conflicting evidence objects (same subject+predicate, opposite polarity)
10. EMIT      report{ baseline_capabilities, reachable_resources, contradictions, uncertainties }
```

Complexity: node count is small (tens–hundreds), so bounded DFS with memoisation is enough. Every
loop is capped (`MAX_STATE_DEPTH`, `MAX_PATHS_PER_QUERY`, `MAX_PATH_LENGTH`) and the caps are
reported so the reader knows whether a result is complete or truncated.

## 2. Authorization rules (must match IAM mental model)

| Rule | Detail |
|---|---|
| Default deny | No matching allow ⇒ not authorized. Never inferred from silence. |
| Explicit deny wins | A deny match overrides any allow match, regardless of order or specificity. |
| Wildcards | `*`, `verb:*`, `res-prod-*`, `arn:...:*` supported; matching is glob, case-insensitive on verbs. |
| Principal binding | A permission binds to an *identity*; a credential contributes the identity it **assumes** (`ASSUMES`), which may differ from the agent's declared identity — this difference is an `ESCALATES_TO` finding when the credential is broader. |
| Conditions | `mfa`, `source_ip_cidr`, `time_window`, `approval_required`. An unmet/unverifiable condition ⇒ capability `status ∈ {probable, possible}` and a listed uncertainty. Conditions never *grant* access. |
| Scope vs environment | A credential with `scope=[staging]` cannot authorize production, even if a policy mentions production (contradiction → report it). |

## 3. Credential validity rules

`valid := (expires_at is None or expires_at > now) ∧ scope_satisfies(target) ∧ audience_unmet ⇒
already_denied`. Outcomes:

| Situation | Report |
|---|---|
| `expires_at` in the past | capability `contradicted` (declared authority present, reachability invalid) |
| `expires_at` None | capability capped at `probable` + uncertainty `credential_expiry_unknown` |
| scope ≠ target environment | capability removed + contradiction if a policy claimed it |
| credential is `discoverable_via` a reachable tool | **new** `ESCALATES_TO` capability with `state_depth = 1` |

## 4. Severity model (deterministic, table-driven)

```
severity_raw = ACTION_WEIGHT[action_class][target.data_class_or_criticality]
severity_env = severity_raw × ENV_MULTIPLIER[environment.tier]      # dev .4 test .5 staging .75 prod 1.0
severity_blk = severity_env, downgraded one step if a blocker applies (approval/dry-run/DLP)
severity_fin = severity_blk, adjusted by recoverability:
                 recoverable            -> unchanged
                 difficult              -> +1 step if action ∈ {DELETE, EXECUTE, DESTROY}
                 potentially_irreversible -> forced to CRITICAL for action ∈ {DELETE, DESTROY}
                 unknown                -> capped at HIGH, + uncertainty
```

Bands: `INFO < LOW < MEDIUM < HIGH < CRITICAL`. Additional caps:

- `actionable ∈ {possible, unverified}` ⇒ **max MEDIUM**.
- `actionable == contradicted` ⇒ excluded from severity, listed under contradictions.
- A capability that is `confirmed` but whose target `criticality == 0` ⇒ **max LOW** (no invented
  business impact for non-critical resources).

Every severity carries `severity_basis: [rule_ids]` so the report can show *why* a band was chosen.

## 5. Evidence model (§17 + §42)

```python
class EvidenceKind(StrEnum):     FACT = "fact"; INFERENCE = "inference"
                                 HYPOTHESIS = "hypothesis"; CONTRADICTION = "contradiction"

@dataclass(frozen=True)
class Evidence:
    id: str                      # "ev-0012"
    kind: EvidenceKind
    subject: str                 # "cred-deploy-token"
    predicate: str               # "authorizes", "reachable_from", "expires_at_past", ...
    object: str | None           # "res-prod-api"
    polarity: bool               # True = supports, False = negates   <-- enables set-algebra
    value: Any | None            # normalized value (never a secret)
    source: Source               # {kind, ref, trusted}
    supports: tuple[str, ...]    # evidence ids this was derived from (for INFERENCE)
    note: str | None             # short human-readable justification
```

Rules:

| Rule | Detail |
|---|---|
| FACTS only from structured input | A fact must cite a concrete `source.ref` inside the parsed input. |
| INFERENCE requires ≥2 supporting FACTS | Otherwise it is a HYPOTHESIS. Enforced, not advised. |
| HYPOTHESIS is never counted as a fact | It may appear in `potential_paths`, never in `confirmed_paths`. |
| High-impact gate | `severity ∈ {HIGH, CRITICAL}` requires **≥2 evidence items of kind FACT**; otherwise the finding is emitted with `verification_status ≤ possible` and a `insufficient_evidence` uncertainty. |
| Untrusted sources cannot create FACTs | `source.trusted == False` ⇒ the derived evidence is at most INFERENCE, and it is tagged `untrusted_derived`. |
| Dedup | identical `(kind, subject, predicate, object, polarity, source.ref)` collapse to one id. |

## 6. Confidence & verification status

Confidence is computed, never generated:

```
conf = w1 * min(1, facts/3) * w2 * source_trust_factor * w3 * precondition_factor
       * w4 * (rejections > 0 ? penalty : 1) * w5 * (contradictions > 0 ? penalty : 1)
```

| Status | Derivation (deterministic) |
|---|---|
| `confirmed` | all preconditions satisfied by FACTs, no contradictions, ≥2 FACTs, credential valid, path deterministic |
| `probable` | exactly one UNKNOWN among preconditions/expiry/authentication, no contradictions |
| `possible` | ≥2 UNKNOWNs, or path requires an LLM-proposed (unpromoted) edge |
| `unverified` | required deterministic check could not run (missing input section) |
| `contradicted` | a CONTRADICTION evidence item exists for this capability |

The numeric `confidence` is **reported next to** the status and evidence count — never instead of
them. Confidence is capped by status (`possible ≤ 0.55`, `probable ≤ 0.85`, `confirmed ≤ 1.0`).
This is the anti-overclaiming device: an LLM cannot inflate its own confidence, because the
verifier recomputes it from evidence.

## 7. Contradiction handling (§41 — a headline feature, not an edge case)

Contradictions are detected by set algebra, not by prose reading:

| Pattern | Example | Report shape |
|---|---|---|
| Authority vs. reachability | `pol-*` grants prod write; `net-*` says prod unreachable | `declared: HIGH / effective: UNREACHABLE / confidence: LOW` |
| Policy vs. credential scope | policy mentions prod; `cred-deploy-token.scope` = staging only | capability removed; contradiction recorded |
| Expiry vs. metadata | `cred-expired-prod.expires_at` in the past but description says "active" | capability `contradicted`, injection/misleading-metadata flag if description came from untrusted source |
| Prose vs. structure | tool description claims admin, `pol-*` says read-only | text rejected; `misleading_metadata` finding against the source |
| Claimed path vs. graph | input asserts `Agent → prod-db` but no valid path exists | `PATH_NOT_FOUND` contradiction (**fake-attack-path defence**, §40) |

Contradictions are **first-class report items** with the conflicting evidence ids on both sides.
They never silently resolve in favour of the more alarming side.

## 8. Investigation state, budgets, and termination (§15 + §16)

The agentic layer's state is explicit, inspectable, and serialised with every run:

```python
class InvestigationState(BaseModel):
    investigation_id: str
    run_mode: RunMode                     # A_deterministic | B_interpret | C_agentic | D_full
    agent_id: str
    environment: str
    # --- facts (from deterministic plane; the LLM may read, never write) ---
    identity: Identity | None
    tools: list[Tool]
    credentials: list[Credential]
    resources: list[Resource]
    network_paths: list[NetworkEdge]
    permissions: list[Permission]
    blockers: list[Blocker]
    # --- derived (deterministic) ---
    baseline_capabilities: list[Capability]
    contradictions: list[Contradiction]
    # --- agentic working set ---
    hypotheses: list[Hypothesis]          # each with hash, status, supporting evidence ids
    proposed_edges: list[ProposedEdge]    # promoted only by the verifier / human
    tool_calls: list[ToolCallRecord]      # name, args, result digest, latency
    analysis_steps: list[AnalysisStep]    # OBSERVE/STATE/HYPOTHESIZE/SELECT/EXECUTE/VERIFY/CONCLUDE
    session_facts: dict[str, Any]         # accumulated during stateful analysis, with provenance
    rejected_claims: list[RejectedClaim]
    # --- output ---
    capabilities: list[Capability]
    risk_findings: list[Finding]
    confidence: dict[str, float]
    terminations: TerminationRecord
    final_conclusion: Conclusion | None
```

### Loop control (all caps are configurable, all breaches are reported)

| Control | Default | Behaviour on breach |
|---|---|---|
| `MAX_AGENT_STEPS` | 12 | stop, `termination_reason = budget_exhausted` |
| `MAX_TOOL_CALLS` | 20 | stop |
| `MAX_LLM_CALLS` | 15 | stop, fall back to A/B results |
| `TIMEOUT_SECONDS` | 90 wall-clock | stop, return partial + explicit `partial: true` |
| duplicate hypothesis | `sha256(normalised hypothesis)` seen before | skip, count `duplicate_hypothesis` |
| loop detection | same (tool, args) pair seen **k** times (k=2) | skip |
| confidence threshold | stop when all HIGH+ capabilities are `confirmed`/`contradicted` and no open hypothesis can change a severity band | normal termination (`reason = verification_complete`) |
| no-progress detection | N consecutive steps without a new graph edge / evidence item / status change | stop (`reason = no_progress`) |

```
termination_reason ∈ {verification_complete, budget_exhausted, timeout, no_progress,
                      duplicate_hypothesis, loop_detected, analysis_complete, error}
```

`analysis_complete` (deterministic-only runs) and `verification_complete` are the only two "clean"
endings; all others must be surfaced in the report's uncertainties, because a truncated analysis is
an analysis with unquantified blast radius.

## 9. Counterfactual operations (§27)

A counterfactual is a *graph edit + a full deterministic re-run* — never a narrative guess:

```python
class CounterfactualOp(BaseModel):
    kind: Literal["remove_tool", "remove_credential", "reduce_scope", "remove_permission",
                  "block_network_edge", "add_blocker", "separate_environment",
                  "remove_mcp_server", "add_dry_run"]
    target_id: str
    detail: dict[str, Any] | None
```

Procedure:

```
1. apply the edit to a COPY of the parsed facts
2. re-run the deterministic engine (mode A) on the copy
3. diff capability sets: removed / downgraded / unchanged / NEW (must be empty; if not, the edit
   was not a pure reduction and the result is flagged `non_monotone_edit`)
4. report {capability, before_severity, after_severity, delta, evidence}
5. rank control recommendations by (severity reduction, capability count removed, side-effect cost)
```

Multi-edit ("minimal control set") = greedy search over ops by marginal severity reduction, with a
hard cap on the number of ops considered (default 3) so runtime stays predictable. Every result is
**analysis only** — nothing is applied to any environment (§28 human-in-the-loop).

## 10. Output contract (the report shape the API and UI both consume)

```jsonc
{
  "analysis_id": "an-2026-09-28-0001",
  "status": "completed",
  "run_mode": "D_full",
  "partial": false,
  "termination_reason": "verification_complete",
  "agent": {"id": "agent-coding-01", "identity": "ident-dev-agent", "declared_environment": "development"},

  "layers": {                                   // §2 of PHASE_0 -- never collapsed
    "declared_authority": {"capabilities": 3, "severity_max": "HIGH"},
    "reachable_authority": {"capabilities": 2, "severity_max": "HIGH"},
    "effective_capability": {"capabilities": 5, "severity_max": "HIGH"},
    "delta_notes": ["1 declared capability not reachable (network)", "3 effective capabilities undeclared"]
  },

  "risk_summary": {"overall_severity": "HIGH", "highest_path": ["cap-0007"],
                   "cross_environment_paths": 1, "destructive_capabilities": 0,
                   "irreversible_capabilities": 0, "uncertainty_count": 4},

  "capabilities": [ /* Capability objects, DATA_MODEL.md §10 */ ],
  "paths": {"confirmed_paths": [], "potential_paths": []},
  "findings": [ {"id": "f-003", "capability_id": "cap-0007", "title": "...",
                 "severity": "HIGH", "severity_basis": ["R3", "ENV_PROD", "BLK_APPROVAL"],
                 "recovery": {"recoverability": "recoverable", "mechanisms": ["rollback"],
                              "evidence": ["ev-0042"]},
                 "evidence": ["ev-0012", "ev-0013", "ev-0042"],
                 "evidence_count": {"fact": 2, "inference": 1, "hypothesis": 0},
                 "verification_status": "probable", "confidence": 0.72,
                 "uncertainties": ["credential_expiry_unknown"],
                 "discovered_by": "deterministic+agentic", "state_depth": 2} ],
  "contradictions": [ {"code": "AUTHORITY_REACHABILITY", "subject": "...", "evidence": ["ev-0007"],
                       "sides": {"declared": ["ev-0007"], "effective": ["ev-0011"]} } ],
  "uncertainties": [ {"code": "no_recovery_facts_for_res-prod-api", "affects": ["cap-0007"]} ],
  "agent_rejected_claims": [ {"claim": "...", "reason": "unknown_entity_id", "source_ref": "..."} ],
  "injection_attempts": [ {"source_ref": "mcp/deploy.json", "pattern": "instruction_override",
                           "handling": "quarantined_as_data"} ],
  "counterfactuals": [ {"op": {"kind": "remove_credential", "target_id": "cred-deploy-token"},
                        "capabilities_removed": ["cap-0007"], "severity_before": "HIGH",
                        "severity_after": "LOW", "non_monotone_edit": false} ],
  "baseline_comparison": {                      // §38 -- always present
    "mode_a_capabilities": 3, "requested_mode_capabilities": 5,
    "added_by_agentic": ["cap-0006", "cap-0007"], "rejected_agentic": ["cap-0099"],
    "notes": ["composition path requires 2 discovery steps"] },
  "trajectory": [ {"step": 1, "phase": "OBSERVE", "summary": "parsed 13 tools, 6 credentials",
                   "evidence": ["ev-0001"]} ],
  "metrics": {"llm_calls": 7, "tool_calls": 9, "input_tokens": 14210, "output_tokens": 2103,
              "latency_ms": 18422, "caps_hit": []},
  "evidence": [ /* all Evidence objects, deduped, with sources */ ]
}
```

**Rendering contract:** `GET /analysis/{id}/report` renders this object as text following the
report layout in master-prompt §18 (DIRECT CAPABILITIES / INDIRECT CAPABILITIES / HIGH-IMPACT PATH /
POTENTIAL IMPACT / EVIDENCE / CONFIDENCE / UNCERTAINTIES). `GET /analysis/{id}/graph` returns nodes
and edges in a JSON form the Gradio graph view and Graphviz export both consume. The text report and
the JSON must be generated from the same object — never maintained separately.


