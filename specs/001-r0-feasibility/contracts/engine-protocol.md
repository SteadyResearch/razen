# R0 Engine, Runtime, and Supervisor Contracts

**Protocol**: `razen.proof/0.1.0`. Related: [data model](../data-model.md),
[pilot profile](pilot-profile.json), [WIT](plugin-sdk.wit), [CLI](proof-cli.md).
This is a local proof interface, not a public HTTP control service or complete agent API.

## Framing and caller binding

One UTF-8 JSON object per LF-terminated line over private pipes/Unix sockets; no PTY.
Reject invalid UTF-8/JSON, duplicate keys, trailing non-whitespace data, unknown fields,
unknown kinds, and frames exceeding the profile limit before unbounded allocation. Integers,
strings, ownership, and versions follow the data model. Binary bodies use bounded Base64
chunks or artifact references, never lossy text conversion. Bound stderr independently;
never treat diagnostic output as instructions or protocol messages.

Each envelope contains exactly:

| Field | Type / rule |
| --- | --- |
| `protocol` | Exact protocol string above |
| `message_id` | Sender-generated UUID v4 scoped to the authenticated binding; duplicate delivery is deduplicated only within that same binding |
| `kind` | Allowed by the authenticated channel role and direction in the runtime or supervisor table below |
| `correlation_id` | Optional UUID v4 referring to an existing message in the same authenticated binding |
| `payload` | Strict kind-specific object, bounded by the profile |

The trusted host creates an authenticated binding to project, user, session, provider digest,
tools, policy revision, and budget. Peer-supplied IDs/grants/roles do not establish authority.
Runtime metadata may identify its originating revision but cannot change the effective one.
No call accepts an arbitrary host path, shell command, raw socket handle, or secret value.

Canonical entity IDs are host-generated UUID v4 strings; opaque references do not confer authority.
Fixed manifest/descriptor catalog IDs (packages such as `R0-01`, cases such as `CON-01`,
profiles such as `macos-arm64-proof`, tools, adapters, and rules) retain their catalog-defined
syntax; they are not subject to canonical UUID requirements. Transport `message_id` and
`call_id` are sender-generated UUID v4 strings scoped to their authenticated binding;
`correlation_id` refers to an existing message in that same binding. None is a grant or
canonical entity identity. Deduplicate message delivery and calls only within the same
binding; a cross-binding collision cannot deduplicate another actor's call. Reject
cross-binding correlations/call references and peer transport IDs offered as canonical
authority; never resolve them through an unscoped ID lookup. Schema validation MUST accept
catalog handles, host-generated canonical UUIDs, and same-binding transport UUIDs in their
respective namespaces and MUST reject malformed UUIDs in UUID namespaces and cross-binding
references. The authenticated host binding, not ID possession, determines authority.

The local control channel is separate from runtime output handling. Use a private 0700 run
directory, 0600 Unix socket, same-user peer checks and a per-run random capability accessible
only to the trusted orchestrator/engine. Do not export that capability or pass it into the
VM/workload. Plain engine/runtime stdio is bound by its parent-created process/pipe identity.
The VM SSH transport has no PTY, agent/X11 forwarding, or workload-accessible management
socket; close all inherited descriptors except the explicitly bounded child stdio pipes.

## Lifecycle and message kinds

| Direction | Kind | Exact payload fields / meaning |
| --- | --- | --- |
| Host → runtime | `start` | `binding_id`, `contract_version`, `context_refs[]`, `tool_ids[]`, `budget_summary`; values are descriptive, not transferable grants |
| Runtime → host | `started` | `capabilities[]`; required capabilities include brokered calls, events/results, usage, cancellation, closure; optional capabilities are declared, not assumed |
| Runtime → host | `tool_request` | `call_id`, `tool_id`, `tool_version`, `input`, `source_control_revision`; host validates all fields and derives authority |
| Host → runtime | `tool_result` | `call_id`, `invocation_id`, `state`, optional `output_ref`, optional `error`, `usage`; successful output and error are mutually exclusive |
| Runtime → host | `event` | `event_type`, `source_control_revision`, `sequence`, `data_refs[]`; untrusted proposal, validated before canonical write |
| Host → runtime | `steer` | `control_revision`, `instruction_ref`; no new authority; optional native capability |
| Host → runtime | `cancel` | `control_revision`, `reason`; host barrier is already active before delivery |
| Runtime → host | `result` | `state`, `source_control_revision`, `proposal_refs[]`, `usage`, optional `error`; state `completed`, `failed`, `cancelled`, or `budget_exhausted` |
| Host → runtime | `close` | `reason`; no further calls admitted |
| Runtime → host | `closed` | Empty object; close resources and retain canonical trace |

Required capabilities do not include a vendor model or native steering. A runtime without
native steering/pause is cancelled or isolated and reconstructed from canonical context;
late messages retain their origin but cannot restart work. R0 supplies a simulated runtime,
including a deliberately blocked variant. No framework owns project state or grants.

The independent model port has `capabilities`, `generate`, and `cancel` operations, each bound
to provider/model/version, selected context references, purpose, output contract, and budget.
R0 advertises an offline simulated provider only: generation returns fixed fixture proposals,
records zero external requests, and cannot carry credentials. A requested real provider returns
`provider_unavailable`; fallback never authorizes data egress. Model and runtime bindings are
separate even when one runtime fixture requests a model operation.

## Minimal tool catalog

All descriptor versions are `0.1.0`; output is strict and host-validated. String fields are
bounded by the message limit, with `rule_id` at most 128 and `title` at most 256 UTF-8 bytes.
Snapshot references carry IDs/revisions, not caller-controlled filesystem paths.

| Tool / effect | Input fields | Successful output |
| --- | --- | --- |
| `traffic.snapshot.read` / local read | `snapshot_id`, `revision`, `offset`, `max_bytes` | `snapshot_ref`, `offset`, `bytes_base64`, `eof`; max read is the chunk limit and remaining budget |
| `http.send` / active network | `request_snapshot_id`, `base_revision`, `identity_id` | `exchange_ref`, `response_snapshot_ref` (omitted only for opaque CONNECT), `timing_ref`; no raw secrets; grant binds the actual prepared request/destination |
| `observation.propose` / local write | `rule_id`, `title`, `snapshot_id`, `revision`, `range_start`, `range_end` | `proposal_id`, `status = proposed`; no confirmed finding is created |
| `context.read` / local read | `kind`, `record_id`; kind `investigation`, `memory_examples`, or `asset_examples` | `record_ref`, `schema_version`; ownership/purpose prefiltered, examples only |

`http.send` resolves an immutable host-published `RawBody` request descriptor at
`request_snapshot_id` / `base_revision`. Its strict canonical JSON fields are
`body_snapshot_id`, `body_revision`, `url`, `method`, `headers`, `request_count`, and
`reset_first_stream`; `derived_from` identifies the separate owned body snapshot.
URL/method limits are 8192/32 UTF-8 bytes, headers are at most 256 entries and 65536
aggregate name/value bytes, and request count is 1–3 within the selected protocol's
stream/reset bounds. Descriptor publication does not approve or dispatch a request.
Preparation binds descriptor/body hashes and revisions, identity, destination and
the host's opaque immutable configuration ID. Private authorization/cookie values
are resolved only during dispatch, never serialized in that descriptor or grant input.
Exact historical deliveries compare the canonical descriptor/body metadata fingerprint
without reopening the request body, dispatching again, or charging again.
Successful invocation output points to the strict three-reference output artifact:
`exchange_ref` resolves the actual exchange record and `timing_ref` resolves measured
monotonic `started_us`, `finished_us`, and `network_elapsed_us`. Ordinary HTTP always
has an actual `response_snapshot_ref`; opaque CONNECT omits it because the proxy
retains no semantic response-body snapshot. Failures/unknown outcomes publish no SDK
success output. Every retained response/partial body, timing, record and SDK output
byte is charged in addition to measured network body usage.

Each raw measurement sample's `result_artifact_id` identifies that exchange record,
not the three-reference SDK output artifact. Provenance MUST resolve the completed
invocation's canonical output, require its `exchange_ref` to equal the sample's result,
and verify both artifacts' kinds, producing invocation, ownership and immutable bytes.
An unlinked same-byte artifact does not establish the measured result.

H2 exchange/error `stream_id` values identify the downstream client leg. The host-owned
exchange record includes at most three `stream_links`, each containing the actually allocated
`downstream_stream_id` and `upstream_stream_id`. Each leg's IDs are distinct positive odd
31-bit values; the proxy legs need not allocate the same number or in the same order.
Receiver facts and reset attribution resolve through this mapping, never numeric equality
between legs. A rejection before upstream stream creation has no fabricated upstream link.

Traffic processing is registered under the same host policy; forwarding does not invoke an
interactive registry operation per packet. The transport port exposes typed connect/forward/
intercept intents and snapshot references, never internal Rama objects to other domains.

## Admission and control barrier

1. Authenticate the binding and validate exact schemas/tool versions.
2. Resolve canonical input/snapshot/identity/destinations and current policy.
3. Validate a current valid host-derived grant, scope and control revisions; atomically reserve
   parent-backed quota with the authorized `reserved` record. Historical grant presence is
   insufficient for reservation/admission, including after revocation.
4. Before each effect, serialize final admission with control-barrier updates. Persist the
   attempt as `sending` and its reservation/outbox records before dispatch. Never hold the
   control admission mechanism across runtime output, guest response, or network waits.
5. Validate and commit output, usage, immutable evidence, and event references, or record a
   precise failure/unknown outcome. New connections/redirects are new scope/control checks.

When multiple grants satisfy every current authority, scope and quota check, reserve against
the grant with the latest expiry. UUID ordering must not let a shorter-lived equivalent
approval shadow a longer current approval. The reservation remains bound to that selected
grant; later rechecks never extend it or substitute another grant after expiry or revocation.

Historical verification treats grant limits as ceilings: each requested units, bytes, CPU-time
and elapsed-time amount MUST be at most the corresponding recorded grant limit, not exactly
equal to it. Retain the original identity/input/version/scope and recorded-admission checks;
do not apply today's expiry or revocation state to a completed historical operation.

The host services control on an independent responsive path. Receipt-to-acknowledgment is
measured by one host monotonic clock. Acknowledgment means the affected revision is advanced,
new affected admissions are blocked, incompatible tickets are invalidated, and the durable
control update has committed. It must meet the profile's one-second deadline even when the
runtime, VM, or network blocks. If the ledger cannot commit, fail closed and report a failed
control proof; do not send a false active-barrier acknowledgment.

An effect already admitted/dispatched before the barrier may remain in flight. Record its
actual send/outcome and originating revision; cancellation cannot undo it. Zero stale
admissions are allowed after the barrier. Pending work is not released by late results or by
restoring an old checkpoint. Mode changes preserve session/evidence/consumption.

Invocation schema validation follows the data model: `grant_id` is omittable, never nullable.
It MUST be absent in `proposed`, `rejected`, and `waiting_approval`, and MUST be present in
`reserved`, `sending`, `completed`, `failed`, and `outcome_unknown`. A `cancelled` record MUST
retain its grant when cancelled from `reserved` and MUST omit it when cancelled before
authorization; recorded transition history establishes provenance, never an invented grant
UUID. Once authorized, retain the historical grant even after revocation, including on later
`cancelled` records, without treating it as current authority. Schema validation MUST accept
these state/provenance combinations, including historical revoked grants, and MUST reject
null grants, grants on preauthorization records, missing grants from `reserved` onward, and
cancelled grant/history mismatches. New reservation/admission MUST reject revoked grants.

## Component host obligations

The WIT world is synchronous and passive. Per invocation, bind the snapshot reference to the
host's project/revision/hash and reject guest substitution. Enforce offset/count arithmetic,
chunk and cumulative byte budgets before copying. Read only requested chunks; validate every
observation's snapshot/range and cumulative output. Empty observation lists are legitimate
only after successful analysis, never a substitute for a trap or timeout.

Use separate Store instances with the profile's memory/table/instance/fuel/epoch limits.
Async host-side operations have independent deadlines/cancellation. WASI imports, if needed
by generated P2 components, receive no environment/arguments/preopens/network or inherited
stdio; capture any diagnostic streams in bounded buffers. Missing ungranted imports fail
instantiation. A supervisor restarts/quarantines the failed runner without terminating the
engine, and a new valid invocation must succeed after each adversarial case. The global RSS
monitor is not represented as a hard resident-memory allocation guarantee.

Enclosing host cancellation and invocation-local cancellation are distinct input signals.
The supervisor MUST observe either without rewriting the caller-owned local flag. On
cancellation, terminate the owned runner group and reap the runner before releasing its
invocation slot.

`component.max_concurrent_invocations = 1` and `component.max_concurrent_host_calls = 1`
are aggregate engine-wide slot limits across all component stores/runners, not per-Store
limits or linear-memory counts. Acquire an invocation slot before starting component work
and a host-call slot before performing brokered host work. At capacity, immediately return
structured `budget_exhausted` without spawning/performing additional work or accumulating
unbounded queues. Release the corresponding slots on success, trap, timeout, or cancellation;
control must remain responsive and a fresh valid invocation must succeed after each variant.
Host-call saturation is exercised through the actual broker, which trusted native fixtures
may drive concurrently even though the WIT world is synchronous and passive. This adds no
guest async import or guest capability and does not change the WIT contract.

## External supervisor binding

Runtime and supervisor channels use the framing envelope above but distinct direction/kind
and payload schemas. The trusted host fixes the channel role when creating the authenticated
transport; no peer-supplied kind/payload may select or change that role. Never fall back from
an unknown supervisor kind to runtime decoding. A supervisor `started` is not a runtime `started`.

All supervisor payloads are strict objects. IDs, counters, versions, hashes and references
follow the data model. The host preallocates canonical IDs, including the launch attestation ID.
The `launch` below resolves only preinstalled approved fixture IDs, never arbitrary commands.
The supervisor validates profile/binding/revision/lease, attests the effective pinned VM
configuration and establishes a dedicated no-sudo workload UID/cgroup and mandatory namespaces
before child release. The workload receives no SSH credentials, manager sockets, host mounts,
ledger paths or cgroup-management handles. Its output is untrusted data, not supervisor messages.

| Direction | Kind | Exact payload fields / meaning |
| --- | --- | --- |
| Host → supervisor | `launch` | `binding_id`, `invocation_id`, `run_id`, `attestation_id`, `profile_sha256`, `approved_fixture_id`, `input_artifact_refs[]`, `lease_id`, `control_revision`; IDs/references are host-bound and the profile is already installed/validated |
| Supervisor → host | `ready` | `invocation_id`, `attestation`; full SandboxAttestation with the launch's host-assigned attestation/run IDs; host validates all checks before accepting readiness |
| Supervisor → host | `started` | `invocation_id`; emitted only after the sandbox/lease is active and child release; no runtime `capabilities` payload |
| Supervisor → host | `output` | `invocation_id`, `stream`, `sequence`, `bytes_base64`; stream is `stdout` or `stderr`, sequence is per stream, decoded chunk/cumulative output obey profile limits; host stores validated chunks as canonical artifacts |
| Supervisor → host | `usage` | `invocation_id`, `cpu_time_us`, `memory_peak_bytes`, `pids_peak`, `tmpfs_peak_bytes`, `output_bytes`; nonnegative observed resource counters, not claims of a hard monitor-enforced RSS ceiling |
| Supervisor → host | `terminated` | `invocation_id`, `outcome`, `empty_cgroup`, optional `exit_code`, optional `signal`; outcome is `completed`, `failed`, `cancelled`, or `budget_exhausted`; empty_cgroup is a measured boolean; exit_code (0–255) and signal (1–64) are mutually exclusive; containment passes only with verified empty-cgroup evidence or recorded VM-stop escalation |
| Supervisor → host | `error` | `invocation_id`, `error`; the structured error defined below, not a runtime result or successful termination |
| Host → supervisor | `lease_refresh` | `binding_id`, `invocation_id`, `lease_id`, `control_revision`; refresh only the matching live lease/current revision, never a restored or terminal lease |
| Host → supervisor | `cancel` | `binding_id`, `invocation_id`, `lease_id`, `control_revision`, `reason`; the host barrier is already active before delivery |
| Host → supervisor | `close` | `binding_id`, `invocation_id`, `lease_id`, `control_revision`, `reason`; admit no new work and verify containment of any live child |

Replies correlate to the same authenticated launch/control request; validate the invocation
against that binding before accepting any reply. The guest watchdog starts its monotonic lease
before child release and refreshes from its own receipt time using the pinned
`external_runner.orphan_lease_ms`, never a host wall-clock subtraction. Refresh requires the
live lease's current revision and cannot extend the invocation wall deadline. A duplicate
message does not refresh its timer. Authenticated cancel/close may advance the revision
monotonically, close the lease immediately, and admit no new work; reject older revisions.
Stale messages, mismatched IDs and terminal leases cannot revive work. Missing controllers,
user namespaces, seccomp, image/version pin, or clean effective configuration block launch;
no native-host or unrestricted-container fallback exists.

Guest cancellation kills the entire invocation cgroup and verifies emptiness. If management
communication fails, the trusted host force-stops the dedicated VM and records containment
status; killing SSH alone is insufficient. Kernel/hypervisor vulnerabilities, side channels,
and a hostile host administrator are not claimed to be solved.

Native network evidence records the last reached primitive, the actual denied primitive and
Linux errno. An unfinished nonblocking connection or readiness deadline is `incomplete`, not
a denial. UDP/DNS records `udp_send_attempted` only when `sendto` actually ran. Healthy controls
must complete within their bounded setup deadline before a denial counts as containment.

Gateway, target and model are distinct controlled TCP fixture roles in the trusted guest
manager's network namespace, outside the workload sandbox. They are not Lima's host-loopback
alias or real model services. Keep `networkOpts.hostLoopback: false`; the pinned Lima backend
intentionally refuses that alias. Each execution MUST provide exactly one healthy,
zero-unauthorized-arrival counter for each of IPv4/IPv6 TCP/UDP, DNS, AF_UNIX, AF_VSOCK and the
three fixture roles. Missing or duplicate families cannot be hidden by another execution's
healthy counters. No LAN listener, host-loopback access or socket forward is enabled.

This distinction follows the [Lima networking contract](https://lima-vm.io/docs/config/network/user/)
and its [pinned gateway mapping](https://github.com/lima-vm/lima/blob/v2.3.0/pkg/networks/usernet/gvproxy.go).

Native setup/run failures preserve the original operation, stage and numeric errno separately
from cleanup failures. Public errors contain only bounded static diagnostic metadata, never
untrusted output or private paths. Root-owned mode-0600 private failure records retain bounded
stream prefixes and explicit truncation metadata. The authenticated management reader accepts
only a canonical invocation ID, validates the frozen preparation and launch binding, and caps
the record at one MiB; each stream prefix is capped at 65,536 bytes. Failure diagnostics never
stand in for a successful attestation, verified cgroup termination or authenticated VM stop.

The trusted pre-release launcher reports a closed operation code and its immediately captured
Linux errno over a separate, fixed eight-byte private pipe. That descriptor MUST close on
successful exec and MUST NOT reach bubblewrap or the workload. The root manager consumes any
launcher failure before accepting a probe or recording a generic setup failure; the original
typed cause remains separate from subsequent cleanup failures. This channel is diagnostic
metadata only, never attestation or containment evidence.

## Independent receiver and crash seams

The controlled receiver runs outside the engine process being killed. Authenticated, loopback
fixture operations are `POST /effect/{action_id}` and `GET /count/{action_id}`. Each POST
increments the counter, including duplicates; the receiver does not hide resends through its
own deduplication. Count responses contain exactly `action_id` and nonnegative `count`.
The orchestrator retains the receiver's address/token and observations outside the killed
engine; none is available to untrusted workloads.

Trusted fixture barriers pause the owned engine at each mandatory seam:

- `before_reservation_commit`: no durable reservation yet.
- `after_reservation_commit`: reservation is durable, but final admission/`sending` has not occurred.
- `after_sending_commit`: final admission is durable, but effect dispatch has not started.
- `after_receiver_increment`: the receiver observed the effect, but completion is not committed.
- `after_completion_commit`: the result and consumption are durable.

The orchestrator sends SIGKILL to that owned engine PID, restarts against the same ledger/current
policy, and compares receiver counts. REC-01 exercises both reservation seams, preserving prior
consumption, reconciling/releasing any unspent reservation, and observing zero POSTs before and
after restart. REC-02 exercises both sending/receiver seams: restore `outcome_unknown` even when
the receiver count is zero, preserve consumption, and perform no automatic resend. No general-
purpose crash/kill API is exposed to a runtime. Reconciliation uses authorized read-only evidence.
Control/scope/grant changes made while the engine is down must be checked before any subsequent
effect admission.

## Errors and evidence

Errors contain `code`, a bounded redacted `message`, `invocation_id` where allocated,
`retryability`, and `diagnostic_refs[]`. Codes: `invalid_input`, `unsupported_version`,
`unknown_tool`, `permission_denied`, `out_of_scope`, `approval_required`, `budget_exhausted`,
`stale_snapshot`, `unsupported_protocol`, `timeout`, `cancelled`, `plugin_trap`, `output_invalid`,
`provider_unavailable`, `outcome_unknown`, `integrity_error`, `isolation_unavailable`.
Retryability is host-assigned `safe_read`, `reconcile`, or `never`; an active unknown outcome
is always `reconcile`. Queue saturation returns an explicit bounded error and marks any lost
required evidence incomplete; do not silently drop events or convert a failure into success.
