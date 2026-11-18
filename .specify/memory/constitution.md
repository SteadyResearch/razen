# Razen Constitution

This constitution governs Razen, the local-first security investigation workbench described in
`docs/base-spec-v0.1.md`, where "Steady" is a provisional product name. It adopts the rules below,
not the source document's entire proposed feature catalog or delivery schedule. Features,
acceptance scenarios, and architecture proposals MUST NOT be presented as implemented merely
because they appear in either document.

The current architectural guidance includes the source document's version 0.2 amendment:
retain the approved Tauri application and make its Rust backend independently runnable on
the local device or an explicitly selected operator-controlled remote device.

## Core Principles

### I. Local-First Manual Utility

The manual workbench MUST remain useful with AI providers and remote services disabled.
Capture, inspection, replay, search, passive analysis, evidence review, and local report export
MUST NOT depend on a model, cloud synchronization, or data contribution. Project data MUST
remain local by default. Remote models, connectors, collaboration, and contribution MUST be
separately enabled and authorized; authorizing a target MUST NOT authorize disclosure of its
traffic or code to a provider. This independence makes the manual product a usable delivery,
not a dependency of later automation.

Local-first MUST mean same-device backend/storage by default, not frontend-owned execution.
Selecting a remote backend MUST be explicit; its project data and execution remain on that
backend. It MUST NOT implicitly enable remote models, cloud synchronization, contribution,
or multiuser/team features.

Source: base specification §§2.2, 3.1, 3.3, 4.8, 4.17–4.18, 5.2, 6.2, 11.1.

### II. Host-Enforced Authorization

The Rust engine MUST own scope, identity, grants, quotas, and action admission. The UI, CLI,
plugins, agents, workflows, scheduled jobs, and integrations MUST use the same policy boundary.
Explicit queries and actions MUST pass through the Tool Registry with versioned schemas,
host-derived authority, effect classification, limits, and redacted audit records. Registered
traffic-processing hooks MUST run under equivalent host policy; each packet need not become
an interactive tool invocation.

Access MUST be denied by default. The host MUST revalidate current scope and permissions before
each connection, redirect, destination change, or delegated effect, including resolved addresses.
Reads, writes, active network access, sensitive actions, and outbound disclosure MUST have
distinct grants. Replay is active regardless of HTTP method. Discovery, memory, skills, model
output, package signatures, and valid IPC connections MUST NOT grant authority. Delegation MUST
only narrow scope and budgets; revocation MUST invalidate incompatible pending work.

Source: base specification §§4.1–4.2, 4.4, 7, 10, 13.1.

### III. Immutable Evidence and Honest Claims

An investigation MUST connect goal, hypothesis, task, tool execution, evidence, validation, and
the next decision, with attribution for human and automated actors. Messages and artifacts MUST
retain immutable originals, versions, hashes, and provenance. Edits MUST produce new versions
against a validated base; stale patches MUST be rejected. Unchanged content MUST preserve its
original body bytes. Truncation, unsupported representations, partial analysis, and failures MUST
be explicit, never silent corruption or empty success.

Findings MUST reference concrete snapshots or commit/content-pinned source, not only mutable
URLs. Confirmation MUST require a stated criterion and validated evidence; a model assertion,
passive indicator, or completed agent run is insufficient. Observations, inferences, hypotheses,
confirmed facts, severity, and confidence MUST remain distinguishable. Status changes and
retests MUST retain reasons, authors, and historical evidence. Coverage MUST state its denominator;
missing findings or exhausted avenues MUST NOT be represented as proof of security.

Source: base specification §§4.6, 4.11, 5.6, 6, 13.1, 18.1.

### IV. Framework-Neutral Core and Isolated Extensions

Domain and application contracts MUST be owned by the product, independent of presentation,
transport types, agent frameworks, and model vendors. Runtime and model adapters MUST remain
separate. The host MUST own canonical state, investigation planning/admission, and workflow
scheduling; runtimes MAY propose steps and results but MUST NOT own authorization. Asset and
investigation graphs, workflow DAGs, and execution traces MUST remain distinct linked contracts.
ARTEX informs the investigation and backend-lifecycle approach, not inherited frontend, code,
capabilities, dependencies, or safety guarantees.

WASM plugins, agent runtimes, and external tools MUST have explicit, versioned contracts and
least-privilege capabilities. Untrusted execution MUST be isolated across the process and its
descendants, with bounded filesystem, network, credentials, resources, output, and cancellation.
Prompts, hidden tools, command filters, and framework hooks MUST NOT substitute for isolation.
If the platform cannot enforce a capability's boundary, that capability MUST be unavailable.
Opening repositories, importing artifacts, or discovering packages MUST NOT execute their code.
SDK examples MUST use public interfaces available to third parties, not private engine APIs.

Source: base specification §§3.3, 5.2–5.3, 6.4, 8–9, 13.1.

### V. Continuous Human Control and Durable Execution

Manual, Copilot, and Autonomous modes MUST share investigation identity, persistent session,
evidence, history, and consumed budget. Supervision is a policy profile and a workflow is a
procedure; neither creates another mode or memory level. Delegation MUST stay within its
selection, purpose, limits, and return-of-control boundary. An analysis request MUST NOT
silently initiate autonomous exploration.

The host MUST accept pause, cancellation, steering, and takeover without waiting for a model.
It MUST advance the affected `control_revision`, block admission of stale actions, invalidate
incompatible tickets, and reconcile in-flight effects. Late results MAY add attributed evidence
but MUST NOT reactivate an obsolete plan. Adapters lacking native control MUST be cancelled or
isolated and reconstructed from canonical context before continuing; stale workers MUST NOT
continue unseen.

Budgets, reservations, leases, attempts, and checkpoints MUST survive restart. Children MUST
consume the parent's aggregate quota. An active effect that may already have occurred MUST be
recorded as `outcome_unknown` and reconciled, never blindly retried. Forks and resumption MUST NOT
replay effects, reset budgets, or clone expired grants. Workflow definitions MUST be version-pinned;
agent replanning MUST NOT rewrite the outer DAG, and iterations/retries MUST be bounded.

Closing Tauri, losing its connection, or sleeping the analyst's laptop MUST NOT cancel or
approve backend work. Already authorized work MAY continue within its grants and limits
while the backend device stays running; pending approvals/interceptions MUST remain blocked
or expire under declared policy. Unattended operation while the laptop sleeps requires a
separate running backend device. Reconnection MUST authenticate and recover canonical state
and event cursors without resubmitting active effects or resetting budgets. A disconnected
client MUST NOT claim live state or an acknowledged control action.

Source: base specification §§5.2, 6.3, 6.5, 9.2, 9.5–9.9, 13.1.

### VI. Exactly Two Local Memory Levels

Local memory MUST have exactly two logical levels: user memory for durable general knowledge,
rules, preferences, and lessons; session memory for a persistent investigation session's history,
decisions, target context, and evidence references. Projects, targets, clients, branches, and
runtime conversations MUST NOT create additional local memory levels.

The host MUST derive user/session identity and prefilter access before searching or expanding
relationships. Retrieval MUST select relevant user memory and the authorized active session,
not implicitly search other sessions or users. Agents and workflows MAY share their investigation
session only within their grants. Canonical history MUST survive window closure, compaction, and
model/runtime changes; summaries MUST NOT replace or erase it.

Session-to-user promotion MUST create a generalized item with lineage, validity, conflict checks,
confidential-data removal, and policy-required review. Captured instructions MUST NOT become
rules, and general rules or requirements MUST change only by explicit user decision. Within host
policy, current instructions and session-specific requirements MUST override general preferences.
Export, retention, backup, and deletion MUST respect both levels independently; sharing MUST be
explicit. No memory item or graph relationship may expand scope or permissions.

Source: base specification §§4.13, 6.5, 10.3, 13.1.

### VII. Phased Delivery and Verifiable Quality

Work MUST be scoped to a reviewed delivery slice with stable requirement identifiers, assigned
acceptance criteria, explicit exclusions, and a reproducible demonstration. R0 feasibility and
security contracts MUST gate R1's manual MVP; R2 adds extensibility/minimal white-box reading,
R3 adds the initial harness, memory, and builder, and R4 adds parallel autonomy/deeper analysis.
R5 team components and optional extensions MUST have separate scope and acceptance decisions.
No slice implicitly commits the full catalog or an inherited schedule.

R1 MUST deliver the independent local/remote backend boundary with the approved Tauri
frontend (FUN-95, CA-81/CA-82). Single-user remote operation MUST NOT depend on R5 team
infrastructure. Earlier R0 evidence MUST retain its original scope and MUST NOT be relabeled
as acceptance of the new product API, frontend lifecycle, or Linux backend deployment.

Claims of protocol, operating-system, language, analyzer, SDK, or adapter support MUST identify
verified combinations and limitations. Proposed performance thresholds MUST NOT be called measured
results or release gates until the hardware, fixtures, versions, and method are agreed in R0.
Done MUST mean implemented behavior, passing assigned scenarios, enforced policy, preserved
evidence, error/cancellation handling, documentation, observability, and reproducible results.
A screenshot, happy-path demonstration, or AI-generated claim alone MUST NOT establish acceptance.

Source: base specification §§2.3, 11–14, 15.2.

## Architecture and Security Constraints

- The retained foundation is an independently runnable Rust backend, the approved Tauri
  desktop frontend, Rama behind a product-owned transport port, a Tool Registry, and a
  WASM/Wasmtime/WIT SDK. A browser-client replacement MUST NOT be introduced without a new
  explicit decision. Begin with modules in one backend crate/process; separate frontend
  builds and security-isolated runner processes do not require microservices or a crate
  per responsibility. Additional services/crates MUST have a concrete scoped need.
  Dependencies MUST point toward domain/application contracts; internal Rama, storage,
  and Tauri objects MUST NOT leak into the plugin API.
- LLM calls MUST NOT enter synchronous traffic forwarding. Heavy analysis MUST use persisted
  references outside that path. Body reads, buffers, decompression, queues, hook duration,
  concurrency, and output MUST be bounded; large payloads MUST use chunks/references instead
  of repeated whole-body copies. Mutator order and failure behavior MUST be deterministic and
  configured before activation.
- Tauri, the backend, and untrusted execution MUST have explicit process boundaries.
  Backend startup, shutdown, jobs, and persistence MUST NOT depend on Tauri's lifecycle.
  Tauri and CLI clients MUST use the same versioned, authenticated backend contract for
  local or explicitly selected remote operation. Private IPC MUST also authenticate callers;
  neither an API connection nor Tauri capabilities replace project/action authorization.
  Control endpoints MUST default to loopback. Remote exposure MUST be explicit, authenticated,
  and encrypted with server identity validation through an approved private/TLS channel.
  Commands, data, and event streams MUST enforce identity/permissions; webview origins MUST
  be restricted. Captured HTML/scripts MUST render inertly; frontend commands stay minimal.
- Project/provider credentials and CA private keys MUST remain in backend-controlled secure
  storage. The Tauri host MAY store backend connection credentials separately; they MUST NOT
  become captured content or authorize project effects by themselves. Plugins, frontend
  renderer code, models, logs, and ordinary exports MUST NOT receive CA private keys. Trust
  installation/removal MUST be explicit; TLS verification MUST NOT be silently disabled.
  Sensitive evidence MUST use maintained authenticated encryption; visible metadata MUST be
  documented. SQLite alone MUST NOT be advertised as full-project encryption.
- Outbound data MUST pass purpose/provider-specific authorization, minimum-context selection,
  redaction, and review controls. Provider fallback MUST NOT disclose data to an unapproved
  recipient. Contribution MUST be disabled by default and consent MUST be independent of
  telemetry, model use, and training. Logs MUST be structured and redacted.
- Plugin permissions MUST be the intersection of declared, granted, project, and execution
  capabilities. Updates MUST NOT silently expand grants or change pinned in-flight versions.
  Published packages MUST have verified integrity/provenance and signatures; unsigned local
  development MUST be explicit and constrained. Neither signatures nor WASM alone prove safety.
- Local and single-user remote profiles MUST keep one writer engine per project, versioned
  migrations, and validated backup/recovery. Authoritative project data, job queues, budgets
  and keys MUST live on the selected backend, not in a frontend replica or shared SQLite
  folder. Frontend upload/import/download MUST be explicit. R5 team deployment adds
  per-resource/tenant authorization and coordination; basic API authentication is required
  before R5.
- Open proposals MUST be resolved at the source document's decision gates, not treated as
  historical agreements: product identity/license before publication; pilot OS, exact dependency
  versions/TLS, isolation backend, at most two pilot language families, and benchmark profile
  in R0; the Tauri UI library before UI work; runtime/providers before R3. Tauri is retained,
  not an open frontend replacement decision. The R1 headless-backend OS/architecture and
  deployment contract MUST be validated separately from the macOS desktop pilot.
  Additional protocols, full encryption, marketplace, and incentives require separate decisions.

Source: base specification §§2.2, 5, 6.2, 8.4–8.6, 10–12, 15.2, 19.

## Development Workflow and Quality Gates

1. Before implementation, each feature specification/plan MUST identify its FUN/CA references
   (or explicitly assign new stable IDs), delivery phase, observable behavior, non-goals, and
   impact on contracts, data, permissions, and acceptance. Estimates MUST state assumptions
   and feasibility evidence; the historical specification supplies no delivery commitment.
2. Before parallel work, owners MUST agree on shared snapshots, errors, events, and policy
   contracts. Material decisions MUST have an ADR and explicit approval by the responsible
   maintainers. Incompatible contract/data changes MUST include versioning and migration or
   explicit rejection behavior. No agent framework, analyzer, or extension may be accepted
   solely through name recognition or claimed compatibility.
3. Each changed invariant MUST have deterministic fixtures and acceptance evidence at the
   appropriate boundary: unit tests for policy/state; integration tests for transport, storage,
   IPC, and adapters; end-to-end analyst/plugin journeys; codec round-trip and parser fuzzing;
   negative tests for scope, isolation, revocation, injection, and disclosure; fault tests for
   shutdown, full disks, cancellation, and uncertain effects. AI evaluations MUST score fixed
   tasks and evidence rather than exact prose. Live models/targets MUST NOT be called deterministic.
   Verification MUST be scoped to the changed boundary and its acceptance criteria. A
   documentation-only synchronization requires consistency checks, not automatic provisioning,
   builds, or rerunning unrelated historical proof suites. No new capability is accepted
   merely by updating these documents.
4. Release review MUST verify the applicable CA scenarios, requirement-to-module-to-delivery-to-test
   traceability, protocol/language/platform matrix, dependency/license/security checks, and
   reproducible performance/recovery results. CI MUST cover formatting, static analysis, tests,
   dependency auditing, and package generation for declared platforms. Manual operation with
   models disabled MUST remain a release journey; every newly available consumer MUST demonstrate
   the same engine policy. Unsupported capabilities MUST be disabled or labeled, not simulated.
5. The responsible reviewer MUST check all seven principles and record compliance or blocking
   deviations. Delivery MUST include documentation, redacted diagnostics, limits, and recovery/
   update procedures. A deferred feature MUST remain explicitly unimplemented; acceptance MUST
   NOT be weakened to disguise incomplete behavior or a missing security boundary.

Source: base specification §§11.3, 12–14.

## Governance

This constitution is authoritative for project governance. Specifications, plans, implementation,
reviews, and runtime-read templates/commands MUST comply with it. The base specification provides
feature detail and provenance; its proposed choices remain proposals until approved. Conflicts
MUST be resolved explicitly before affected work proceeds, not by silently weakening policy.

An amendment MUST state its rationale, affected principles and FUN/CA/ADR references, compatibility
impact, migration or rollout requirements, and compliance evidence. Project maintainers MUST
review and approve it. Amendments MUST preserve still-applicable decisions, update this document's
version and amendment date, and identify unresolved items. A temporary Sync Impact Report MUST
accompany review and be removed before the amended constitution is committed. Adoption here
MUST NOT silently modify the source specification, templates, commands, or application artifacts.

Constitution versions MUST follow semantic versioning: MAJOR for incompatible governance changes
or principle removals/redefinitions; MINOR for new principles/sections or materially expanded
guidance; PATCH for non-semantic clarifications and corrections. Version 1.0.0 establishes the
first substantive constitution, independently of the base specification's 0.1 version.
Ratification MUST retain the original adoption date once confirmed; Last Amended MUST record the
date of the latest substantive edit in ISO 8601 calendar format.

Every specification/plan review, pull request, and release review MUST assess constitutional
compliance. Violations MUST block acceptance unless an approved amendment resolves them; ADRs,
skills, memory entries, and implementation convenience MUST NOT override this constitution.

**Version**: 1.1.0 | **Ratified**: TODO(RATIFICATION_DATE): confirm original adoption date | **Last Amended**: 2026-11-18
