# Feature Specification: R0 Feasibility and Shared Contracts

**Feature Branch**: Not created; no branch hook is configured.

**Created**: 2026-11-16

**Status**: R0 implemented; 35/35 mandatory proofs passed; explicit maintainer exit approval pending.

**Input**: Read `docs/base-spec-v0.1.md` as the product baseline, use the latest dependency
versions, and start with just R0 rather than specifying the complete product.

**Original proof baseline**: [Product specification](../../docs/base-spec-v0.1.md),
content version 0.1 dated 2026-11-16, especially §§5–11, §12 R0, §13 CA-65, and §15.2.
The [constitution](../../.specify/memory/constitution.md) governs all work.

## Baseline Amendment Scope

The current general specification is content version **0.2** and the constitution is **1.1.0**.
The approved frontend remains **Tauri**, not a browser client. Its Rust backend must have an
independent lifecycle and the same authenticated local/remote API; execution and canonical
data belong to the selected backend, not to the frontend connection.

That product deployment contract is **R1 FUN-95, CA-81/CA-82**, not an extension of these R0
proofs. The completed local harness and its private runtime/supervisor IPC do not establish
the product frontend API, unattended service deployment, or a supported remote Linux backend.
Frontend disconnection is distinct from losing a backend-owned worker's control transport.
Keep completed R0 tasks, research decisions, contracts, pins, and sealed evidence at their
recorded scope. Future R1 work must validate the new boundary without relabeling R0 results.

## Clarifications

### Session 2026-11-16

- Q: Must R0 successfully forward HTTP/1.1, tunnel HTTPS, intercept HTTPS with authorization,
  and forward HTTP/2 before it can pass? → A: All four modes must succeed; expected errors
  count only for negative test cases.
- Q: May R0 add its test certificate authority to the operating system's trust store, or must
  trust stay inside the test client? → A: Trust stays inside an isolated test client;
  R0 must not modify operating-system trust.
- Q: Must the R0 recovery proof survive actually stopping and restarting the proof process,
  or is a fixture-only simulation sufficient? → A: Require a real process restart with a
  minimal saved checkpoint, preserved budget, current grant checks, and no automatic resend.
- Q: How quickly must R0 acknowledge a pause or cancellation request while its simulated
  runtime is blocked? → A: Within 1 second on the agreed pilot test profile; acknowledgment
  means the host has activated the control barrier and blocked new affected actions.

### Session 2026-11-17

- Q: Should R0 reject leap-second timestamps such as `23:59:60Z`? → A: Reject them explicitly;
  preserve ordinary UTC timestamps, precision and ordering without silent normalization.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Agree on shared contracts (Priority: P1)

As a technical lead, I can inspect and exercise a small, versioned set of shared contracts so
independent feasibility proofs agree on authority, evidence, errors, and execution state.

**Why this priority**: Networking and extension experiments must not establish incompatible
versions of project identity, policy, or evidence.

**Independent Test**: Review the contract pack and run representative valid and invalid
examples without a desktop interface, target connection, or model provider.

**Acceptance Scenarios**:

1. **Given** example project, scope, tool, invocation, snapshot, and event records, **When**
   they are checked against the contract, **Then** valid records retain stable references and
   incompatible versions, invalid fields, stale evidence, and missing authority are rejected.
2. **Given** the same denied operation submitted by two simulated consumers, **When** the host
   evaluates it, **Then** both receive the same policy outcome before any effect occurs.
3. **Given** example asset, investigation, workflow, trace, and memory records, **When** they
   are linked, **Then** their meanings remain separate and local memory has only user and
   session levels; a runtime conversation introduces no third level.

---

### User Story 2 - Demonstrate authorized traffic handling (Priority: P1)

As a transport evaluator, I can send controlled laboratory traffic through the proposed
transport foundation and compare it with direct traffic before committing to the manual MVP.

**Why this priority**: Protocol fidelity, scope enforcement, and TLS handling are blocking
feasibility questions, not capabilities to infer from a dependency's name.

**Independent Test**: Use controlled clients and servers with agreed fixtures; no production
target, full history viewer, repeater, plugin catalog, or AI service is required.

**Acceptance Scenarios**:

1. **Given** required happy-path fixtures for HTTP/1.1 forwarding, HTTPS CONNECT tunneling,
   authorized HTTPS interception, and HTTP/2 forwarding, **When** each flow is exercised,
   **Then** all four succeed, expected semantics and bodies are preserved, and capture
   references identify the representation. An unsupported required mode blocks R0.
2. **Given** excluded addresses, a redirect outside scope, and changing name resolution,
   **When** a connection is attempted, **Then** the actual destination is checked and denied
   effects never reach the excluded receiver.
3. **Given** a test certificate authority and an unsupported protocol/encoding, **When** the
   fixture runs, **Then** explicit trust configuration is confined to an isolated test client,
   operating-system trust remains unchanged, private keys stay out of ordinary outputs, and
   unsupported traffic is rejected or tunneled by profile, never described as inspected.

---

### User Story 3 - Contain component failures (Priority: P1)

As an extension evaluator, I can run one minimal component against the proposed public
contract and observe that invalid or excessive behavior cannot escape its grants or crash
the host.

**Why this priority**: A plugin format alone does not establish a safe extension boundary.

**Independent Test**: Execute a small fixture component and adversarial variants without a
plugin manager, marketplace, production SDK, or reference feature plugin.

**Acceptance Scenarios**:

1. **Given** a component with permission to read one bounded snapshot, **When** it returns a
   valid observation, **Then** the host validates the result and links it to that snapshot.
2. **Given** variants that loop, overallocate, emit oversized/invalid output, request an
   ungranted resource, or block a host call, **When** they run, **Then** configured limits
   terminate or reject them, host-call deadlines are enforced independently, and the host
   remains able to complete a subsequent valid invocation.
3. **Given** a stale patch or another project's reference, **When** a component submits it,
   **Then** it is rejected without changing evidence.

---

### User Story 4 - Prove a neutral, controlled runtime boundary (Priority: P1)

As an automation evaluator, I can exercise a simulated decision runtime and an adversarial
external process through product-owned contracts without granting either control over policy.

**Why this priority**: Framework neutrality, enforceable process isolation, and human control
are prerequisites for later automation. Hidden tools or prompts are not isolation.

**Independent Test**: Run a simulated adapter and restricted external process with local fixture
inputs; no real model, selected agent framework, autonomous investigator, or workflow engine
is required.

**Acceptance Scenarios**:

1. **Given** a simulated runtime that proposes permitted and forbidden calls, **When** the host
   admits work, **Then** only authorized calls run, the product retains canonical state, and
   runtime choice does not change tool, evidence, or policy contracts.
2. **Given** a process and descendants attempting ungranted file reads, credential access,
   direct target/model connections, or privilege escape, **When** the isolation proof runs,
   **Then** each attempt is blocked independently of the process's text or tool names.
3. **Given** blocked runtime output and pending actions, **When** the host receives a pause or
   cancellation request, **Then** within 1 second on the agreed pilot test profile it advances
   the affected control revision, blocks new affected actions, and acknowledges the active
   barrier. No stale action is admitted afterward; already-sent effects and late results
   retain their originating revision.
4. **Given** a simulated runtime with consumed budget, a saved checkpoint, and an active effect
   whose outcome is uncertain, **When** the proof process is forcibly stopped and restarted,
   **Then** quota is restored from saved state, versions and current grants are rechecked, and
   a controlled local receiver confirms that the uncertain action is not automatically resent.

---

### User Story 5 - Make an evidence-based R0 exit decision (Priority: P2)

As a maintainer, I can review the proof results, selected dependency versions, open risks,
and recorded decisions to decide whether the project is ready to specify R1.

**Why this priority**: The evidence from the blocking proofs must precede an implementation
commitment or estimate. Producing an exit report does not make failed proofs pass.

**Independent Test**: Review an exit packet against its agreed fixture inventory, decision
register, and rerun instructions without implementing any later-phase feature.

**Acceptance Scenarios**:

1. **Given** completed proof attempts, **When** the R0 packet is reviewed, **Then** every
   required case has an observed outcome, evidence, versions, limitations, and a reproducible
   method; failed or unexecuted mandatory cases prevent a passing exit.
2. **Given** a proposed dependency selection, **When** it is approved, **Then** it records the
   current stable release source, resolution date, exact chosen version, compatibility and
   license checks, and any explicitly approved exception rather than a floating version.
3. **Given** unavailable isolation on a proposed platform, **When** feasibility is assessed,
   **Then** that capability is marked unavailable; R0 cannot pass without at least one
   enforceable backend on the selected pilot platform.

### Edge Cases

- A permitted hostname resolves or redirects to an excluded address: revalidate the actual
  destination; do not inherit permission from the original name.
- A component's CPU budget expires while a host operation blocks: cancel the host operation
  under its own deadline as well as interrupting the component.
- A sandbox blocks the parent but not a child process: the isolation proof fails.
- A runtime lacks native pause or steering: block host admission, cancel/isolate it, and
  reconstruct from canonical context before continuing.
- Cancellation arrives after sending: retain the result or `outcome_unknown`; do not claim
  the effect was undone or automatically repeat it.
- An event/result arrives twice or after its revision is invalidated: retain attribution and
  deduplicate effects; late evidence must not reactivate the obsolete plan.
- A body is truncated, compressed beyond limits, or represented semantically rather than as
  original wire frames: label the representation and limit; never silently substitute data.
- A current stable dependency is incompatible, withdrawn, or cannot be verified: record the
  blocker and seek an explicit version decision; do not silently downgrade or use a prerelease.
- A proof cannot run or produces no usable evidence: record not verified/blocked, not success.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: R0 MUST deliver the five bounded work packages below as feasibility proofs,
  shared contracts, and a reviewable exit packet; it MUST NOT implement or specify the complete
  product catalog.
- **FR-002**: The contract pack MUST define versioned project/scope identity, typed tool inputs
  and outputs, effects, grants, quotas, invocation states, errors, cancellation, and immutable
  snapshot/patch references, with valid and invalid examples.
- **FR-003**: The pack MUST define distinct linked asset, investigation, workflow, and trace
  structures; an investigation session; and exactly two local memory levels with ownership,
  access, provenance, validity, and promotion boundaries. R0 requires contract examples, not
  working memory retrieval, a graph explorer, or a workflow scheduler.
- **FR-004**: Every proof capable of an effect MUST use host-derived authority and common
  scope/permission enforcement. Denied and revoked actions MUST produce explicit errors before
  effects. Child work MUST NOT gain scope or quota beyond its parent.
- **FR-005**: The transport proof MUST successfully demonstrate HTTP/1.1 forwarding, CONNECT
  tunneling, authorized HTTPS interception, and HTTP/2 forwarding using a declared client/server/
  TLS/encoding matrix. All four required happy paths MUST succeed with forwarding fidelity,
  bounded capture, and destination checks. Unsupported modes and expected errors MUST NOT
  satisfy a required happy path; negative cases MUST produce their explicit expected errors.
- **FR-006**: Certificate-authority creation and installation/removal of trust inside an isolated
  test client MUST be explicit and documented. R0 MUST NOT modify operating-system trust.
  Private keys and fixture credentials MUST NOT appear in component context, simulated model
  payloads, ordinary exports, or diagnostic logs.
- **FR-007**: The component proof MUST use the proposed public host–guest contract, bounded
  snapshot access, host-validated outputs, and explicit grants; internal host structures and
  unrestricted filesystem/network access MUST NOT be required.
- **FR-008**: Component and host-call resource limits MUST cover time, memory, bytes, output,
  and aggregate concurrency across all component stores/runners in one engine. Tests MUST
  demonstrate saturation rejection, slot release on every terminal path, failure containment,
  and a successful valid invocation after each adversarial failure, not merely an error report.
- **FR-009**: A simulated runtime MUST demonstrate start, context delivery, brokered calls,
  events/results, usage, cancellation, and closure. Runtime and model boundaries MUST remain
  independent; a selected real agent framework or model provider is not required in R0.
- **FR-010**: The external-process proof MUST cover the process and descendants, restrict
  filesystem and egress, withhold inherited secrets, and attempt real prohibited reads and
  connections. Merely inspecting a configuration or filtering command names is insufficient.
- **FR-011**: The simulated control channel MUST accept intervention independently of runtime
  responsiveness. On the agreed pilot test profile, pause/cancellation MUST be acknowledged
  within 1 second of host receipt. Acknowledgment MUST mean the control barrier is active:
  the affected revision has advanced and incompatible pending actions are blocked. The proof
  MUST record the limits of cancelling effects already sent.
- **FR-012**: Recovery verification MUST forcibly stop and restart the proof process using a
  minimal durable checkpoint. It MUST demonstrate preserved quota, current version/grant
  revalidation, duplicate-event handling, and reconciliation of `outcome_unknown` without
  automatic resending, verified against a controlled local receiver. Replaying restored-state
  fixtures alone is insufficient; production project storage remains outside R0.
- **FR-013**: Dependency selection MUST begin with the latest stable, non-prerelease releases
  available from authoritative upstream sources when planning or executing R0. The selected
  compatible set MUST have exact reproducible pins, a dated source/compatibility/license
  record, and explicit review of exceptions. Floating `latest` and silent downgrades are
  prohibited; proof results apply to recorded versions, not to untested future releases.
- **FR-014**: Before measurement, evaluators MUST record hardware, operating system, fixtures,
  workload, version set, limits, and method. They MUST measure the relevant baseline latency,
  resource use, failure containment, and cancellation behavior and retain raw results.
  Proposed product thresholds are hypotheses to validate, not claims already achieved.
- **FR-015**: The R0 decision register MUST resolve the pilot platform, exact dependency/TLS
  choices, enforceable isolation backend, at most two initial language families, and benchmark
  profile. It MUST record decisions on process boundaries, initial persistence/encryption,
  model/runtime contracts, and permissions with rationale, limitations, and decision status.
- **FR-016**: Every mandatory proof MUST have a rerun procedure, observable expected outcomes,
  actual results, and source/requirement references. The exit packet MUST distinguish passed,
  failed, blocked, and unexecuted cases and identify consequences for subsequent work without
  creating later-phase specifications or promising a schedule.
- **FR-017**: Proof traces MUST identify caller, project/session where relevant, tool/contract
  version, grant decision, destination, control revision, attempt, usage, evidence, and outcome,
  with secrets redacted and references instead of whole bodies by default.
- **FR-018**: Unsupported capabilities MUST be declared unavailable or rejected explicitly.
  A passing R0 exit MUST require all mandatory proofs, including CA-65, and enforceable
  isolation on the selected pilot; disabling the required pilot proof is not a passing result.

### Key Entities *(include if feature involves data)*

- **Work Package**: Stable R0 identifier, bounded outcome, prerequisite packages, mapped
  requirements, and independently reviewable proof.
- **Contract Pack**: Versioned definitions and positive/negative examples for authority,
  evidence, events, investigation state, and the separate runtime/model boundaries.
- **Proof Case / Result**: Fixture identity, expected outcome, actual status, environment,
  version set, resource limits, evidence references, and repeatable execution instructions.
- **Invocation / Checkpoint**: Actor, authority, input version, control revision, attempt,
  budget usage, state, and references needed to reconcile interruption without replay.
- **Dependency Record**: Upstream source, date checked, latest stable candidate, selected exact
  version, compatibility/license evidence, pin, and explicitly approved exception if needed.
- **Decision / Exit Packet**: Alternatives, selected outcome, rationale, evidence, unresolved
  blocker, responsible reviewer, and consequences for readiness to specify R1.

### R0 Work Packages and Dependencies

Dependencies are proof prerequisites, not a requirement to finish the desktop application.
The identifiers below are local R0 feature boundaries, not new baseline FUN or CA identifiers.
Once R0-01's shared contracts are agreed, R0-02, R0-03, and R0-04 can proceed independently.

| ID | Bounded outcome | Hard dependencies | Requirements | Acceptance |
| --- | --- | --- | --- | --- |
| R0-01 | Shared authority, evidence, event, investigation, and adapter contracts with examples | None | FR-002, FR-003, FR-004, FR-017 | Story 1; SC-001, SC-002 |
| R0-02 | Laboratory transport and TLS fidelity/scope proof; no manual workbench | R0-01 | FR-004, FR-005, FR-006, FR-014, FR-017 | Story 2; SC-002, SC-003 |
| R0-03 | Minimal public component contract and supervised failure-containment proof; no SDK product | R0-01 | FR-004, FR-007, FR-008, FR-017 | Story 3; SC-002, SC-004 |
| R0-04 | Simulated neutral runtime, control/recovery contract, and adversarial external-process isolation | R0-01 | FR-004, FR-009, FR-010, FR-011, FR-012, FR-017 | Story 4; SC-002, SC-004, SC-005 |
| R0-05 | Dated version/decision register, benchmark evidence, and R0 exit review | R0-01, R0-02, R0-03, R0-04 | FR-001, FR-013, FR-014, FR-015, FR-016, FR-018 | Story 5; SC-006, SC-007 |

**Source coverage**: R0-01 covers baseline §12 R0's Tool Registry and investigation/asset/
evidence/trace schemas, informed by §§6–7. R0-02 covers its network/TLS spike (§5).
R0-03 covers its component contract and limits (§8). R0-04 covers its simulated runtime and
external-process isolation (§9.7 and CA-65; ADR-11–13; FUN-87–88's R0 contract/proof scope).
R0-05 covers its initial language selection, ADRs, benchmark profile, feasibility results, and
planning inputs (§11, §12 R0, §15.2). Later-phase FUN-87–88 delivery is not pulled into R0.

### Scope Boundaries

Included: fixture-only prototypes, shared contract examples, adversarial tests, measured
feasibility results, explicit architectural decisions, and the R0 exit packet.

Excluded: the R1 manual MVP, headless product-service deployment, Tauri local/remote client API
(FUN-95), production project storage, full desktop/CLI journeys, production SDK/package manager
and reference plugins, semantic source analysis, working user/session memory, actual AI
investigations or swarms, visual workflows, integrations/team service, marketplace/contribution/
incentives, and specifications for R1–R5. A small local proof harness is allowed; it MUST NOT
be advertised as any of those products.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All five R0 packages have a bounded outcome, dependency list, source mapping,
  and independent acceptance procedure; every required contract example has an explicit
  valid/invalid expectation and observed result.
- **SC-002**: Every denied operation in the agreed authority matrix is rejected before its
  effect, repeated cases yield consistent outcomes across simulated consumers, and zero
  fixture secrets appear in prohibited outputs.
- **SC-003**: All four required traffic modes successfully forward their happy-path fixtures
  with the declared message semantics and body representation preserved. Every negative case
  produces its explicit expected rejection/error; no unsupported required mode counts as a
  pass, and every excluded destination receives zero prohibited effects.
- **SC-004**: Every adversarial resource/escape or aggregate-concurrency saturation case is
  blocked or stopped within its predeclared limit, the host remains responsive, occupied
  slots are released after success/trap/timeout/cancellation, and a subsequent permitted
  invocation succeeds. No tested descendant bypasses the same restrictions.
- **SC-005**: On the agreed pilot test profile, pause/cancellation acknowledgment activates
  the control barrier within 1 second of host receipt, even with a blocked runtime. Zero new
  effects from the affected stale revision are admitted afterward. Every forced-stop/restart
  case restores consumed quota from a durable checkpoint, rechecks current grants/versions,
  and reconciles uncertain effects with zero automatic resends at the controlled local receiver.
- **SC-006**: Every selected dependency and required R0 decision has a dated, reviewable record;
  every measured result identifies the environment and exact version set and can be rerun
  from the recorded instructions. No proposed threshold is labeled a measured pass.
- **SC-007**: A reviewer can account for every mandatory case as passed, failed, blocked, or
  unexecuted. A passing exit has zero failed/blocked/unexecuted mandatory cases, includes the
  isolation and cancellation evidence required by CA-65, and contains no later-phase product
  specification or unsupported implementation claim.

## Assumptions

- The recorded R0 proof baseline is content version 0.1 dated 2026-11-16. The current general
  specification's version 0.2 deployment amendment is scoped above, not retroactive proof.
  Exact dependency versions are resolved and verified during planning/execution, not guessed
  or frozen from the baseline's date.
- "Latest versions" means latest stable at a recorded resolution time, with exact pins and
  deliberate upgrade review. Upstream releases during a running proof do not silently change
  that proof's environment; adopting one requires rerunning affected evidence.
- macOS is the baseline's proposed pilot, not a claim of tested support. R0 confirms the
  selected pilot and isolation backend; a full Windows/Linux matrix is outside this phase.
- Only controlled local/laboratory systems and fixture secrets are used. Real target traffic,
  confidential repositories, remote model access, and operating-system trust changes are
  outside R0's scope.
- Numeric product-performance targets in baseline §11.1 remain proposed. R0 establishes the
  reproducible measurement profile and recommends supported targets; it does not have to
  deliver the later MVP's full load, search, or long-duration acceptance results.
- Memory, graph, and model-adapter examples establish contracts, not complete later-phase
  implementations. Recovery additionally requires a minimal durable checkpoint and a real
  forced process restart; it does not require production project storage.
- R0 results can inform subsequent estimates and immediate next-work decisions. Team allocation,
  delivery dates, full-product feature decomposition, and R1–R5 specifications are not supplied
  or committed by this specification.
