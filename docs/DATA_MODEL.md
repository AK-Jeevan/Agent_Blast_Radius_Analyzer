# Data Model (Phase 0, formal) — Agent Blast-Radius Analyzer

Implements §23 + §24 of the master prompt. Every entity below becomes a Pydantic v2 model in
`app/schemas/` during Phase 1 with the *same names and field names* used here. The analysis engine
may not consume a field that is not declared in this document.

## 0. Global conventions

| Rule | Detail |
|---|---|
| IDs | Lowercase, globally unique, stable, type-prefixed: `agent-001`, `ident-dev-agent`, `tool-deploy`, `cred-deploy-token`, `res-prod-db`, `pol-0042`, `net-agent-to-db`, `blk-approval-prod`. |
| Unknown data | Every field that is optional in reality is `Optional[...] = None`. `None` means **UNKNOWN** — never "false", never "allowed". `None`-driven uncertainty must appear in the report. |
| Trust labels | Any string field that can come from an untrusted source carries `source: {kind, ref, trusted: bool}`. `trusted=false` text is **data-only** and can never enter an instruction position. |
| Secrets | Secret values are never represented. `Credential` has no `value` field — only `secret_ref` (locator) and optional `has_value: bool`. |
| Time | `expires_at` ISO-8601 UTC or `null`; durations ISO-8601 (`PT1H`). |
| Determinism | Collections participating in closure math are sorted before hashing so runs are byte-reproducible and diffable (required by the ablation study, §38). |

## 1. Environment

```jsonc
{
  "id": "env-prod",
  "name": "production",
  "tier": "production",        // development | testing | staging | production | unknown
  "criticality": 3,            // 0..3 (derived from tier unless overridden)
  "multiplier": 1.0,           // severity multiplier; set only when a scenario overrides the default
  "boundary": "prod-net",      // network boundary label used for egress checks
  "notes_untrusted": "..."     // data-only prose
}
```

## 2. Identity

Declared identity and each credential's *assumed* identity are separate objects on purpose: the gap
between them is where privilege escalation hides.

```jsonc
{
  "id": "ident-dev-agent",
  "type": "service_account",   // service_account | iam_role | oauth_client | api_identity |
                               // github_app | user | unknown
  "name": "developer-agent-role",
  "environment": "development",      // null allowed (cross-environment identity)
  "provider": "aws",                 // aws | gcp | azure | github | internal | unknown
  "principal_ref": "arn:aws:iam::111:role/dev-agent",
  "trusted_for": ["read", "deploy"], // verbs this identity is *intended* for (declared intent)
  "assumable_by": ["ident-dev-agent"], // who may assume it -> escalation edges
  "source": {"kind": "config", "ref": "agent.json#identity", "trusted": true}
}
```

## 3. Tool (the semantic surface)

```jsonc
{
  "id": "tool-deploy",
  "name": "deploy",
  "description_untrusted": "Deploys the current revision to the selected environment.",
  "actions": ["DEPLOY"],                  // closed taxonomy, PHASE_0 §5
  "action_evidence": [                    // REQUIRED for every claimed action
    {"action": "DEPLOY", "method": "name_match", "method_confidence": 0.6,
     "span": "deploys the current revision", "needs_llm_review": false}
  ],
  "targets": ["res-staging-api", "res-prod-api"],   // addresses ([] = unknown)
  "target_selector": {"param": "environment", "values": ["staging", "production"],
                      "closed_vocabulary": true},   // can the tool name an arbitrary target?
  "input_schema": {"type": "object", "properties": {
      "environment": {"type": "string"}, "ref": {"type": "string"},
      "dry_run": {"type": "boolean"}}},
  "output_schema": {"type": "object", "properties": {"deployment_id": {"type": "string"}}},
  "requires_credentials": ["cred-deploy-token"],
  "side_effect": true,
  "destructive": false,
  "reversible": true,
  "preconditions": [                       // deterministic precondition model
    {"kind": "credential_present", "ref": "cred-deploy-token"},
    {"kind": "network_reachable",  "ref": "net-agent-to-ci"},
    {"kind": "session_fact",       "ref": "fact:current_revision"}
  ],
  "discovery_capability": ["res-prod-api"], // resources the OUTPUT can reveal (state growth)
  "blockers": ["blk-approval-prod"],        // controls gating execution
  "source": {"kind": "mcp_metadata", "ref": "mcp/deploy.json", "trusted": false}
}
```

**Critical:** `description_untrusted` never influences authorization, reachability, or severity. It
may only (a) be shown to the LLM as *data*, and (b) adjust confidence of an `interpreted` action —
never of a `confirmed` one.

## 4. Credential

```jsonc
{
  "id": "cred-deploy-token",
  "type": "service_token",        // api_key | access_token | oauth_token | service_token |
                                  // env_var | mounted_secret | temp_credential | unknown
  "secret_ref": "env:CI_DEPLOY_TOKEN",  // locator ONLY
  "issuer": "ci.internal",
  "scope": ["staging", "production"],      // environment/resource scopes
  "permissions": ["deploy"],               // verbs
  "audience": ["https://ci.internal"],
  "expires_at": "2026-12-31T00:00:00Z",    // null = UNKNOWN -> report as uncertainty
  "assumed_identity": "ident-deploy-svc",
  "discoverable_via": ["tool-read-env", "tool-read-file"],  // escalation input
  "max_privilege_available": true,         // grants more than the holder's declared role
## 5. Resource

```jsonc
{
  "id": "res-prod-db",
  "name": "prod-db",
  "type": "database",      // service | database | bucket | repository | pipeline |
                           // secret_store | queue | compute | endpoint | dns | unknown
  "environment": "production",
  "data_class": "customer_pii",   // public | internal | confidential | customer_pii |
                                  // secret_material | none
  "criticality": 3,               // 0..3
  "recovery": {                   // RecoveryProfile (PHASE_0 §6); null fields = UNKNOWN
    "recoverability": "difficult",
    "mechanisms": ["snapshot"],
    "latest_recovery_point": "PT1H",
    "mean_time_to_recover": null,
    "evidence": ["ev-0042"]
  },
  "dependents": ["res-prod-api"], // DEPENDS_ON in-edges (fan-out of impact)
  "source": {"kind": "inventory", "ref": "cloud/production.json", "trusted": true}
}
```

## 6. Permission (declared authority = L0)

```jsonc
{
  "id": "pol-0042",
  "principal": "ident-deploy-svc",
  "effect": "allow",                    // allow | deny   (explicit deny always wins)
  "actions": ["deploy", "read:logs"],   // verb or verb:qualifier globs
  "resources": ["res-staging-api", "res-prod-api"],   // ids or glob patterns
  "conditions": [{"kind": "mfa", "value": true},
                 {"kind": "source_ip_cidr", "value": "10.0.0.0/8"},
                 {"kind": "time_window", "value": "business_hours"}],
  "via": "cred-deploy-token",           // policy may hang off a CREDENTIAL, not the agent
  "evidence_note": "declared in prod-iam.json",
  "source": {"kind": "iam_export", "ref": "prod-iam.json", "trusted": true}
}
```

`conditions` are not ignorable: an unmet condition downgrades the capability to
`probable`/`possible` and must be listed in that finding's uncertainty list.

## 7. Network edge / path

```jsonc
{
  "id": "net-agent-to-db",
  "source": "ident-dev-agent",   // or a container/host node id
  "target": "res-dev-db",
  "protocol": "tcp/5432",
  "egress": "internal",          // internal | vpn | internet | blocked
  "reachable": true,             // false = explicit denial (firewall / air-gap fact)
  "authenticated": null,         // null = UNKNOWN (never conflated with false)
  "authenticated_via": ["cred-dev-token"],
  "boundary": "dev-net",
  "evidence": ["ev-0011"],
  "source": {"kind": "netpol", "ref": "network.yaml", "trusted": true}
}
```

**Four independent truth values per path** — `reachable`, `authenticated`, `authorized`,
`actionable` — where

```
actionable := reachable ∧ authenticated ∧ authorized ∧ tool_expressive ∧ preconditions_met
```

## 8. Relationship vocabulary (typed, directed edges — §24)

| Relationship | From → To | Meaning | Produces capability? |
|---|---|---|---|
| `USES` | Agent → Tool | agent may invoke tool | yes (unlocks tool actions) |
| `REQUIRES` | Tool → Credential | tool needs the credential to act | gate (precondition) |
| `AUTHORIZES` | Credential → Resource | credential authorizes access to resource | yes |
| `ASSUMES` | Credential → Identity | credential impersonates identity | yes (identity escalation) |
| `HAS_ACCESS_TO` | Identity → Resource | direct identity access (from IAM) | yes |
| `CAN_READ` / `CAN_WRITE` / `CAN_DELETE` / `CAN_EXECUTE` / `CAN_DEPLOY` | Identity \| Credential → Resource | action-specific authority (L0 fact) | yes |
| `DEPENDS_ON` | Resource → Resource | technical/business dependency (impact fan-out) | no (propagates impact) |
| `DEPLOYS_TO` | Tool \| Pipeline → Resource | publish/promote target | yes |
| `CONNECTS_TO` | Resource / Node → Resource | network reachability edge | prerequisite |
| `DISCOVERS` | Tool \| Resource → Resource \| Credential | output reveals this entity (**state growth**) | yes (indirect) |
| `ENABLES` | Resource \| Tool → Capability | step that unlocks another step | yes |
| `ESCALATES_TO` | Credential \| Identity → Identity \| Credential | privilege escalation edge | yes (**closure trigger**) |
| `BACKS_UP` | Resource → Resource | backup/snapshot exists (recovery fact) | no (severity modifier) |
| `GATED_BY` | Tool \| Resource → Blocker | control that gates execution | no (severity reducer) |
| `IN_ENVIRONMENT` | any → Environment | membership label | no (classification) |
| `CONTRADICTS` | Evidence → Evidence | conflicting facts found | no (confidence reducer) |

**Rule:** an edge may only be *asserted* by the deterministic layer (parsed from input). The LLM may
*propose* an edge, but a proposed edge is stored as `hypothesis_edge` and is not traversable until a
deterministic rule (or explicit human confirmation in the UI) promotes it.

## 9. Graph model (one heterogeneous `networkx.MultiDiGraph`)

```text
node attributes:  {kind: agent|identity|tool|credential|resource|blocker|environment|node,
                   environment: str|None, criticality: int, data_class: str|None,
                   trust: trusted|untrusted, layer: L0|L1 }

edge attributes:  {rel: <one of §8>, evidence: [ids], confidence: float,
                   source: {kind, ref, trusted}, action: str|None, hypothesis: bool}
```

Layered views are derived (never stored redundantly):

| View | Sub-graph | Used by |
|---|---|---|
| `identity_view` | agent, identities, credentials, ASSUMES/ESCALATES_TO | privilege-escalation closure |
| `reachability_view` | nodes, CONNECTS_TO, reachable flags | network closure (L1) |
| `authority_view` | principal, CAN_*, AUTHORIZES, permissions | L0 declared authority |
| `capability_view` | tool, actions, targets, blockers | effective capability (L2) |
| `impact_view` | resources, DEPENDS_ON, BACKS_UP, recovery | impact + recovery (L3) |

Because a multi-di-graph is used, parallel edges (e.g. a `CONNECTS_TO` *and* an `AUTHORIZES` between
the same pair) are preserved — they must be reported separately ("network-reachable but not
authorized" is a headline finding, not a dedup casualty).

## 10. Capability object (the unit of output)

```jsonc
{
  "id": "cap-0007",
  "action": "DEPLOY",                       // taxonomy class
  "target": "res-prod-api",
  "environment": "production",
  "path": ["agent-001", "USES", "tool-deploy", "REQUIRES", "cred-deploy-token",
           "AUTHORIZES", "res-prod-api"],
  "path_hash": "sha256:...",                // loop/duplicate detection key
  "path_length": 6,
  "preconditions": [
    {"kind": "network_reachable", "ref": "net-agent-to-ci", "satisfied": true},
    {"kind": "credential_valid",  "ref": "cred-deploy-token", "satisfied": "unknown"}
  ],
  "blockers": ["blk-approval-prod"],
  "reachability": {"reachable": true, "authenticated": true,
                   "authorized": true, "actionable": "probable"},
  "severity": "MEDIUM",                     // capped by actionable status + blockers
  "recoverability": "recoverable",
  "verification_status": "probable",        // confirmed|probable|possible|unverified|contradicted
  "confidence": 0.72,
  "evidence": ["ev-0012", "ev-0013", "ev-0042"],
  "discovered_by": "deterministic|agentic|deterministic+agentic",
  "state_depth": 2,                         // how many discovery steps were needed
  "counterfactual_sensitivity": 0.61        // how much this capability relies on fragile edges
}
```

`state_depth = 0` ⇒ direct capability; `≥ 1` ⇒ indirect/emergent. This single field is what makes
the deterministic-vs-agentic comparison measurable.
