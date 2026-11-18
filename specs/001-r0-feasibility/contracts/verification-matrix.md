# R0 Verification Inventory

**Inventory version**: `0.1.0`. Every row is mandatory for a complete R0 exit. All rows describe
future execution, not results already observed. Capture fixture/profile/version digests, actual
assertions, duration, usage, errors, and immutable evidence for each case. This is the exact
35-case minimum; implementation may add cases but must not remove/weaken these requirements.

[Profile](pilot-profile.json) supplies resource/deadline values; [interfaces](engine-protocol.md)
define authority and state. Baseline CA-65 is exercised by R0-04 and the aggregate exit.
Negative cases pass only when the stated denial/failure is actually observed. Every denied
operation must also show that a corresponding permitted operation/receiver is functional;
absence of a server or a no-op fixture is not isolation evidence.

## R0-01 — Shared contracts

| Case | Required observation | Requirements | Success |
| --- | --- | --- | --- |
| CON-01 | Valid project, scope, descriptor, snapshot, strict snapshot/artifact evidence references, event, invocation, and checkpoint examples round-trip with stable references and versions | FR-002, FR-017 | SC-001 |
| CON-02 | Invalid/unknown versions, extra or duplicate fields, malformed IDs, oversized frames, invalid numeric/range values are rejected before allocation/effect beyond limits; bounded seeded mutation of checked-in valid/invalid byte corpus exercises the real framing codec and typed contract parser, asserting valid-record round-trip/invariants and explicit invalid-input rejection, with saved counterexample replay | FR-002, FR-004 | SC-001, SC-002 |
| CON-03 | Stale patches, hash mismatch, foreign-project evidence and unauthorized identity references are rejected; original evidence remains unchanged | FR-002, FR-004 | SC-002 |
| CON-04 | Harness and simulated-runtime consumers obtain identical denials for equivalent calls; revoked grants and child scope/quota escalation cannot admit effects | FR-004, FR-017 | SC-002 |
| CON-05 | Four distinct asset/investigation/DAG/trace contracts link correctly; user/session memory examples prefilter ownership and reject third levels/cross-session access | FR-003 | SC-001, SC-002 |

## R0-02 — Transport and isolated trust

| Case | Required observation | Requirements | Success |
| --- | --- | --- | --- |
| NET-01 | Plain HTTP/1.1 forwarding succeeds with expected method, target, legal duplicate headers, binary body, and captured references | FR-005, FR-017 | SC-003 |
| NET-02 | CONNECT establishes an authorized opaque TLS tunnel; receiver bytes are correct and no inspection claim is made | FR-005, FR-006 | SC-003 |
| NET-03 | HTTPS HTTP/1.1 interception succeeds with client-local fixture root and independently verified upstream trust; no verification bypass or OS trust change | FR-005, FR-006 | SC-002, SC-003 |
| NET-04 | HTTPS HTTP/2 interception forwards H2 on both legs with ALPN evidence, two concurrent streams, semantic headers and exact unchanged bodies; no H1 downgrade counted as H2 | FR-005 | SC-003 |
| NET-05 | Exclusions, redirect pivots, DNS changes, mapped addresses, and ungranted loopback/private ports deny actual connections; reachable controlled receivers observe zero prohibited effects | FR-004, FR-005 | SC-002, SC-003 |
| NET-06 | Invalid upstream certificates and mismatched CONNECT/SNI/request authorities fail explicitly; client trust can be removed; before/after OS trust records match; secrets/key-log markers absent from prohibited outputs | FR-005, FR-006, FR-017 | SC-002, SC-003 |
| NET-07 | Oversized/truncated bodies and unsupported protocols/encodings produce their declared bounded behavior; no incomplete replacement, silent corruption, or unsupported inspection claim | FR-005, FR-018 | SC-003 |
| NET-08 | Resetting one H2 stream does not corrupt a concurrent valid stream; limits and visible per-stream errors remain attributable | FR-005, FR-014 | SC-003 |

## R0-03 — Component contract and containment

| Case | Required observation | Requirements | Success |
| --- | --- | --- | --- |
| CMP-01 | Component built against the public WIT reads permitted chunks and proposes valid ranges without private engine APIs; unchanged input body remains byte-identical | FR-007, FR-017 | SC-001, SC-004 |
| CMP-02 | Infinite guest computation is interrupted by configured fuel/epochs/deadline, not by waiting for the guest to cooperate | FR-008 | SC-004 |
| CMP-03 | Excess memory/table/instance growth hits hard per-Store guest limits; simultaneous invocation attempts across distinct component Stores/runners saturate the engine-wide `max_concurrent_invocations` cap and immediately return structured `budget_exhausted` without starting extra work or unbounded queuing; engine/control remain responsive; measured runner RSS behavior is recorded without claiming a hard OS cap | FR-008, FR-014 | SC-004 |
| CMP-04 | Oversized/invalid observation lists, overflowed offsets, stale snapshots and foreign-project references fail with explicit validated errors | FR-007, FR-008 | SC-002, SC-004 |
| CMP-05 | A blocked host body-read operation through the actual broker hits its independent `host_call_deadline_ms`/cancellation even when fuel/epoch interruption alone cannot stop it; concurrent trusted native fixture calls through that broker saturate engine-wide `max_concurrent_host_calls` across component Stores/runners and immediately return structured `budget_exhausted` without performing extra work or unbounded queuing; control remains responsive | FR-008 | SC-004 |
| CMP-06 | Ungranted filesystem/socket/environment/credential imports and access attempts fail; no host directories, CA private keys, or credentials are disclosed | FR-006, FR-007, FR-008 | SC-002, SC-004 |
| CMP-07 | After EACH CMP-02 through CMP-06 adversarial variant, including invocation/host-call saturation and success/trap/timeout/cancellation slot-release paths, all held aggregate slots are released and the engine and a fresh permitted invocation succeed; trace attributes the original failure rather than returning empty success | FR-008, FR-017 | SC-004 |

## R0-04 — Runtime, process isolation, and recovery

| Case | Required observation | Requirements | Success |
| --- | --- | --- | --- |
| RUN-01 | Simulated adapter starts, consumes scoped context, proposes brokered calls, emits events/results/usage, cancels and closes; separate simulated model boundary makes zero external calls | FR-009, FR-017 | SC-001, SC-002 |
| RUN-02 | Effective VM/global configuration, image/version/provision hashes, UID, namespaces, seccomp and controllers are attested; contaminated/missing settings block launch without native fallback | FR-010, FR-018 | SC-002, SC-004 |
| RUN-03 | Workload and fork/exec descendants perform real denied reads of host/management/other-invocation canaries and credential paths; a granted snapshot remains readable | FR-006, FR-010 | SC-002, SC-004 |
| RUN-04 | Actual IPv4/IPv6 TCP/UDP/DNS, loopback/gateway/target/model, Unix-manager-socket and AF_VSOCK attempts are blocked; reachable observers see zero unauthorized arrivals; inherited descriptors grant no escape | FR-004, FR-010 | SC-002, SC-004 |
| RUN-05 | Fork/thread, memory, tmpfs and output floods meet cgroup/size/deadline policy; privilege/namespace/cgroup/descriptor escape attempts fail; host survives and the next valid invocation succeeds | FR-010, FR-014 | SC-004 |
| RUN-06 | With runtime reads/output blocked and cancellation ignored, host activates/acknowledges the barrier by the profile deadline, denies all later stale calls, and observes child-cgroup termination or recorded VM-stop escalation | FR-011, FR-017 | SC-004, SC-005 |
| RUN-07 | Duplicate and late events/results keep original causality/revision, deduplicate effects, and never reactivate obsolete pending work or expand quota | FR-004, FR-011, FR-012 | SC-002, SC-005 |
| RUN-08 | Killing host/SSH transport expires the independent guest lease, terminates descendants, and prevents orphan effects; killing only SSH is not accepted as termination evidence | FR-010, FR-011, FR-012 | SC-004, SC-005 |
| REC-01 | SIGKILL at both before_reservation_commit and after_reservation_commit (before final admission) restores prior consumption, reconciles/releases any durable unspent reservation, and observes zero receiver POSTs before/after restart without dispatching the old command | FR-012 | SC-005 |
| REC-02 | SIGKILL at after_sending_commit (before dispatch) and after_receiver_increment (before completion commit) restores `outcome_unknown` even for zero arrivals, preserves consumption, performs only authorized read-only reconciliation, and causes zero additional POSTs | FR-012, FR-017 | SC-005 |
| REC-03 | SIGKILL after completion commit, duplicate events, and old lease messages do not duplicate an effect or reset budget; evidence/result references remain consistent | FR-012, FR-017 | SC-005 |
| REC-04 | Scope/grant/control changes while the engine is down invalidate incompatible restored work; current versions and identities are checked before any new effect | FR-004, FR-011, FR-012 | SC-002, SC-005 |
| REC-05 | Full disk, failed sync, damaged ledger, or incompatible checkpoint blocks new admission with visible partial evidence; unknown effects are not guessed safe or blindly resent | FR-012, FR-016, FR-018 | SC-005, SC-007 |

## R0-05 — Reproducibility and exit

| Case | Required observation | Requirements | Success |
| --- | --- | --- | --- |
| EXIT-01 | Version/decision register records authoritative stable observations, exact resolved pins/checksums/licenses, pilot/TLS/backend/language/persistence choices, hardware/profile, raw measurements and rerun instructions | FR-013, FR-014, FR-015, FR-016 | SC-006 |
| EXIT-02 | All five packages and mandatory cases are accounted for with consistent immutable evidence; failed/blocked/unexecuted cases, missing approval or evidence, changed hashes, and unsupported required modes prevent a passing approved exit; no later-phase product/spec is claimed | FR-001, FR-016, FR-018 | SC-001, SC-007 |

## Measurement and coverage rules

- Measure direct and proxied latency on the same warm local fixture using the profile's sample
  counts/body size; report p50/p95 and observed resource peaks separately from hard gates.
  No model, WAN, compilation, or VM provisioning belongs in those timings.
- CON-02 uses stable-Rust seeded mutation without a new framework, nightly toolchain, or
  dependency. Record the profile digest, checked-in corpus digest, seed, mutation-generator
  version (`parser_fuzz.mutation_version`), actual input count, maximum input size, elapsed
  time, oracle results, and saved counterexample bytes/replay results. Execute the full
  `parser_fuzz.max_inputs` budget within `max_input_bytes` per input and `deadline_ms` overall;
  missing budgets/evidence, early truncation, timeout, panic, or unbounded behavior prevent
  pass. Replay saved counterexamples through the same real codec/parser; no-throw-only or
  source-string assertions do not establish the round-trip/invariant/rejection oracles.
- Component `linear_memory_bytes`, `instances`, `memories`, `tables`, and `table_elements`
  are per-Store limits, not aggregate concurrency bounds. The two component concurrency
  caps apply across all Stores/runners of one engine, independently of those Store limits.
  The approved policy profile is now `0.2.0`: three core Wasm instances, one memory,
  and two tables per Store. Native startup measurements of the public WASI component
  required the additional internal instances/tables; both engine-wide concurrency caps
  remain one. Historical `0.1.0` profiles retain their original one-instance/one-table
  ceilings. This amendment is not a claim that the component proof cases have passed.
  Record configured caps, overlapping attempts, peak admitted work, immediate saturation
  denials, absence of extra work/unbounded queues, slot release on success/trap/timeout/
  cancellation, and fresh successful invocations after every saturation/failure variant.
  Host-call saturation uses concurrent trusted native fixtures through the actual broker;
  the synchronous passive WIT world needs no new async import. Record independent host-call
  deadlines and host-receipt-to-durable-barrier acknowledgements during saturation; each
  control sample must meet `control.ack_deadline_ms` (1 second). Missing limits or missed
  budgets/deadlines prevent pass; responsiveness alone is not saturation/recovery evidence.
- Runtime control timing starts at host receipt and ends only when the durable barrier is
  active and acknowledged. Record actual elapsed time for each sample, not a rounded mean
  that hides a deadline violation. Repeat RUN-06 ten times; every sample must pass.
- For recovery, record receiver count before/after actual engine termination and after
  restoration. The receiver must stay alive, and it must count duplicate POSTs rather than
  masking them. No restored-state mock alone satisfies REC-01 through REC-04.
- Every denied operation includes a healthy permitted control, actual attempted operation,
  explicit result, and independent observation where applicable. Test descendant variants
  under the same invocation limits. Resource maxima have the kernel limitations described
  in research; do not promise instantaneous kill or zero transient allocation overshoot.
- Baseline CA-65 requires typed adapter events/cancellation AND real prohibited-resource
  tests. Passing a config check alone does not satisfy it. Changes to a dependency, image,
  policy, WIT, or profile require new affected results and a newly reviewed aggregate exit.
