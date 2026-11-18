# Implementation Plan: R0 Feasibility and Shared Contracts

**Branch**: `001-r0-feasibility` | **Date**: 2026-11-16 | **Spec**: [spec.md](spec.md)

**Planning record**: Clarified R0 specification; the original design preceded implementation.
Current proof status is recorded in [quickstart.md](quickstart.md), not inferred from this plan.

**Synchronized 2026-11-18**: Constitution 1.1.0 and general specification content version 0.2
retain Tauri and require an independently running local/remote backend in R1. Follow
[Baseline Amendment Scope](spec.md#baseline-amendment-scope). This R0 plan does not implement
that API/service, create a browser client, or authorize a new R1 delivery.

## Summary

Implement a small fixture-driven Rust proof harness for the five R0 packages: shared
authority/evidence contracts; authorized transport/TLS; public component isolation; a neutral
simulated runtime with external-process isolation and durable recovery; and a reproducible
exit packet. Use the retained Rama/Wasmtime/WIT foundation, explicit Rustls trust, a minimal
SQLite proof ledger, and a dedicated Lima VZ Linux VM with per-invocation restrictions.

All four required transport modes must succeed. Trust stays inside isolated test clients;
the engine must survive real forced restart without blind resend; and host control must
activate/acknowledge its barrier within one second even if runtime or VM communication blocks.
The [research register](research.md) resolves versions, alternatives, budgets, and caveats.

## Technical Context

**Language/Version**: Rust 1.100.0; observed stable channel dated 2026-11-12. The installed
1.93.1 is insufficient for selected Rama/Wasmtime MSRVs. Use an exact workspace toolchain and
separate native-Linux and `wasm32-wasip2` fixture workspaces; do not cross-build them as macOS
host targets. Initial source-audit families are Rust and JavaScript/TypeScript, by decision
only; no analyzer or frontend is implemented in R0.

**Primary Dependencies**: Rama 0.4.0, Wasmtime/wasmtime-wasi 50.0.2, wit-bindgen 0.63.0,
Tokio, Serde/serde_json, Rustls with one ring provider, rcgen, UUID, SHA-256, rusqlite, URL/IP
parsing; Linux-only libc/seccompiler for supervised syscall fixtures/filter compilation.
Exact observed stable versions, MSRVs, licenses, and sources are in research D-01. Install no
Tauri/frontend/model framework for this phase. Revalidate stable/non-yanked status before
implementation resolution; review exact direct pins and each workspace's generated lockfile.

**Storage**: Single-writer fixture-only SQLite via bundled rusqlite; rollback journal,
FULL synchronization and macOS fullfsync, checked foreign keys, bounded lock waits.
Transactionally persist quota, control revision, invocation/attempt and outbox references
before effects. Independent receiver counters survive engine SIGKILL. No production project
store, full encryption, or exactly-once network claim is implied.

**Testing**: The 35-case [verification matrix](contracts/verification-matrix.md) covers strict
contracts, deterministic seeded mutation fuzzing of real framing/typed parsers, actual
transport/receiver observations, aggregate component/host-call saturation, adversarial
components/descendants, control timing, and real forced restart. Use stable-Rust test targets
and the profile's finite fuzz budget/corpus provenance, not a new nightly/tool dependency.
All commands in [quickstart.md](quickstart.md) are post-implementation acceptance targets,
not tests run here; no live model or changing external target is needed.

**Target Platform**: macOS 26.5.1 arm64 pilot. Native host and Wasmtime runner; Lima 2.3.0
VZ/plain with pinned Debian 13.7 arm64 image, bubblewrap 0.13.1, AArch64 seccomp, mandatory
namespaces and cgroup-v2 limits. Installed Lima 2.1.1 must be upgraded explicitly. The raw
image selection avoids an unverified qemu-img dependency. Native external macOS tools and
other operating systems remain unavailable in this R0 backend.

**Project Type**: Local proof harness and minimal public component/runtime contracts. It is
not the product CLI, manual workbench, full SDK, agent engine, or deployment service.

**Performance Goals**: At most one second from host control receipt to active durable barrier
acknowledgment; zero stale admissions after it, denied effects, or automatic uncertain-effect
resends. Other finite limits and repeat/sample counts are fixed in the
[pilot profile](contracts/pilot-profile.json) and matrix. Product p95 latency/search/load
thresholds remain hypotheses; record direct/proxy timing and resource observations honestly.

**Constraints**: No OS trust changes, credential inheritance, direct workload egress, ungranted
host mounts/manager sockets, floating dependency selectors, unreviewed fallback, or silent
empty success. Use immutable referenced bodies and bounded chunk reads, not repeated whole-body
copies. No synchronous model/analysis work in forwarding. No framework owns policy/state.

**Scale/Scope**: Five bounded R0 packages, one host ledger writer, at most one component
invocation and one component host call across all stores/runners per engine, and one external
invocation at a time. Saturation is rejected before spawning/effects, without unbounded queues;
slots release on success, trap, timeout and cancellation. Local fixture targets, a simulated
runtime/provider, and exactly two memory-level contract examples are sufficient. No full
graphs, retrieval engine, workflow scheduler, swarm, or team mode is implemented.

## Constitution Check

*Initial and post-design PASS entries are the original R0 design assessments, not runtime
proof results or acceptance of the later R1 deployment rules in constitution 1.1.0.*

| Principle / constraint | Initial | Post-design | Evidence / enforcement |
| --- | --- | --- | --- |
| I. Local-first manual utility | PASS | PASS | Explicit provisioning separated from offline proofs; no model/cloud requirement |
| II. Host authorization | PASS | PASS | Strict host-bound tools, current scope/grants/revisions, shared admission and aggregate quota |
| III. Immutable evidence | PASS | PASS | Snapshot/hash/range validation, original/derived distinction, explicit error/unknown results |
| IV. Neutral core and isolation | PASS | PASS | Product-owned ports/WIT/runtime contract; real supervised component/VM descendant proof |
| V. Human control and durability | PASS | PASS | Independent priority control, durable revision barrier, actual SIGKILL/receiver recovery |
| VI. Two local memory levels | PASS | PASS | User/session examples with ownership prefilter and reviewed promotion; no third level |
| VII. Phased verifiable delivery | PASS | PASS | R0-only inventory; every mandatory failure/blocked/unexecuted case prevents exit |
| Retained architecture and trust | PASS | PASS | Rust/Rama/Wasmtime/WIT retained; Tauri remains the approved frontend but is not implemented in R0; no system trust mutation |
| Versioning, data, and secrets | PASS | PASS | Stable source-backed selections, lockfile/image provenance, fixture-only data and host-memory keys |

No constitutional exception is approved. The constitution's ratification-date metadata TODO
does not authorize guessing an adoption date. R0's host/SSH-loss containment tests cover
backend-owned worker leases, not the Tauri connection or backend-service lifecycle.
Runtime/build/isolation/measurement gates were unexecuted when this plan was created; their
completed record is in the quickstart. FUN-95 and CA-81/CA-82 remain future R1 acceptance.

## Project Structure

### Documentation (this feature)

```text
specs/001-r0-feasibility/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── pilot-profile.json
│   ├── plugin-sdk.wit
│   ├── engine-protocol.md
│   ├── proof-cli.md
│   └── verification-matrix.md
└── checklists/requirements.md
```

`tasks.md` belongs to `/speckit.tasks` and is not generated by this command.

### Source Code (repository root)

The following is the intended implementation layout, not files created during planning:

| Responsibility | Package | Package path | Binaries |
| --- | --- | --- | --- |
| Host engine and proof orchestration | `razen-engine` | `crates/engine` | `razen-proof`, `razen-engine`, `razen-component-runner`, `razen-fixture-receiver` |
| WASI component fixtures | `razen-component-fixtures` | `fixtures/components` | None; `cdylib` components |
| Linux supervisor and adversarial fixtures | `razen-runner-fixtures` | `fixtures/linux-runner` | `razen-tool-supervisor`, `razen-sandbox-adversary` |

```text
Cargo.toml                      # host workspace; excludes both fixture workspaces
Cargo.lock
rust-toolchain.toml
crates/engine/                  # host package
├── src/
│   ├── domain/                 # policy, state, evidence; no Rama/Wasmtime/SQLite objects
│   ├── application/            # admission, priority control, quota and orchestration
│   ├── adapters/               # Rama, Wasmtime supervisor, SQLite, guest transport
│   └── bin/
│       ├── razen-proof.rs
│       ├── razen-engine.rs
│       ├── razen-component-runner.rs
│       └── razen-fixture-receiver.rs
└── tests/                      # contract, transport, component, runtime/recovery proofs
fixtures/
├── components/                 # independent cdylib workspace + Cargo.lock; WASI P2 only
├── linux-runner/               # independent workspace + Cargo.lock; built in pinned guest
│   └── src/bin/
│       ├── razen-tool-supervisor.rs
│       └── razen-sandbox-adversary.rs
└── scenarios/                  # reviewed data and golden expected observations
scripts/proofs/                 # explicit reviewed provisioning/config preparation only
target/r0-evidence/             # owned run packets; generated, not committed source
```

**Structure Decision**: One portable host package is enough for R0; keep Linux-only and
component artifacts in independent workspaces so host checks never compile incompatible
targets. Internal modules separate domain from adapters without a crate per future module.
No desktop, product CLI, production plugin packages, or all-catalog module tree is scaffolded.

## Phase 0 — Resolved research

[research.md](research.md) records decisions, rationale, alternatives, official sources, and
observed version metadata for toolchain/dependencies, transport/TLS composition, Component Model
bindings, VM/process isolation, transactional recovery, pilot budgets, and execution order.
There are no unresolved planning choices or approved version/policy exceptions.

Build compatibility, VZ image boot, effective guest controls, four-mode fidelity, hard timing,
and receiver-observed no-resend are the feasibility experiments themselves, not assumptions
that can be declared successful by a design review.

## Phase 1 — Design and contracts

- [data-model.md](data-model.md) defines identities/ownership, proof records, immutable evidence,
  scope/grants/quotas, invocation states, durable checkpoint/outbox, control timing, runtime/
  sandbox attestation, two-level knowledge examples, and version/decision records.
- [engine-protocol.md](contracts/engine-protocol.md) defines strict framing, lifecycle, minimal
  tools, admission/control semantics, component/guest boundaries, receiver/crash seams, and
  structured errors. [plugin-sdk.wit](contracts/plugin-sdk.wit) is the public passive proof
  world, not a production SDK.
- [proof-cli.md](contracts/proof-cli.md) and [quickstart.md](quickstart.md) define honest command
  status/evidence and post-implementation validation. [verification-matrix.md](contracts/verification-matrix.md)
  maps all requirements/success criteria to actual proof observations.
- [pilot-profile.json](contracts/pilot-profile.json) is the canonical versioned resource,
  deadline, image, and measurement configuration. Hash the exact profile into every run.

### Execution design

The trusted orchestrator owns engine/receiver child processes. The engine owns policy, secrets,
the ledger, transport effects, immutable evidence, and control. Component execution is a
supervised native runner; external runtimes execute only inside the dedicated restricted VM.
All peer data remains untrusted, with effect authority derived by the engine.

US1 owns the common Invocation, Checkpoint, ControlState, ControlMeasurement, and
Event/OutboxEntry models before its parser and ledger consumers. It also implements the
priority host control loop and durable revision-barrier service, including timed acknowledgments
and stale-admission rejection. US3 reuses this working path during component saturation without
waiting for US4. US4 adds RuntimeBinding, Lease, and runtime-specific control/recovery behavior;
it reuses the shared types and handler rather than introducing a second schema or barrier.
Canonical entity IDs, fixed catalog handles, and binding-scoped peer message/call IDs have
distinct validators. Grant presence follows invocation state: preauthorization omits it,
authorization assigns it, and cancellation retains historical assignment without making a
revoked/expired grant current authority.

Within each proof story, finish required module/provider wiring before running passing
integration checks. For a clean validation run, explicitly build all component variants and
host binaries, then prepare/check the guest, then run all-target lint/workspace tests.
No prerequisite build or VM provisioning occurs inside a timed proof or a test pretending
to be an already prepared environment.

The single ledger writer services control updates with priority; no transaction holds a lock
across network/runtime waits. Control closes affected in-memory admission immediately, durably
advances the revision, invalidates incompatible pending tickets, and only then acknowledges.
Disk failure or delayed synchronization makes the proof fail closed, not acknowledge falsely.
Guest termination runs afterward and cannot block the host's control acknowledgment.

The receiver stays alive across owned engine SIGKILL and deliberately counts duplicate POSTs.
The engine commits admission/usage before sending and completion afterward; uncertain effects
are reconciled read-only. Restart does not rehydrate expired grants or replay commands.

R0-01 establishes the contracts. R0-02, R0-03 and R0-04 then proceed independently against them.
R0-05 may prepare measurement/review tooling early but cannot pass before all mandatory evidence.
The original next step was task generation. [tasks.md](tasks.md) now records completed R0
implementation; do not regenerate those checkboxes as new R1 deployment work.

### Risks and execution gates

- Rama's Rustls example is not a ready-made four-mode proxy: verified upstream trust, strict
  authority matching, per-egress address checks, and H2 ALPN/fidelity must actually be proven.
- Lima defaults/global overrides and guest management authority can bypass an apparently
  clean instance configuration. Attest effective state and attempt real parent/descendant
  operations; no fallback when namespaces/seccomp/controllers are missing.
- Fuel/epochs cannot stop blocked host calls, RSS sampling is not a hard native allocation
  cap, and cgroup limits/kill have documented kernel caveats. Retain independent deadlines
  and observed termination/resource evidence rather than promising absolute containment.
- Stable release metadata and declared MSRVs do not prove the selected set builds. A changed
  upstream release or failed resolution requires an explicit pin/register decision and new
  evidence; no silent downgrade, prerelease, or backend replacement is approved.
- The one-second durable barrier depends on actual storage/scheduler behavior. Measure every
  control sample with a blocked runtime; a missed deadline blocks the R0 exit.

## Complexity Tracking

No constitutional violation or exception. The VM plus per-invocation restrictions is justified
by hostile-process/descendant isolation, not framework preference. Separate fixture workspaces
are justified by incompatible compilation targets. Reject production infrastructure, custom
cryptography, a handwritten recovery log, extra framework wrappers, and a future-module crate
tree until the bounded proof demonstrates a concrete need.
