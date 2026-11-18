# R0 Research and Decisions

**Resolved**: 2026-11-18. **Scope**: [R0 specification](spec.md), not the full product.
Research establishes design choices and observed upstream metadata. It does not establish
successful dependency resolution, builds, VM boot, protocol support, isolation, or benchmarks.
Those are mandatory R0 execution results.

## D-01 — Current stable toolchain and dependencies

**Decision**: Select Rust 1.100.0 and the exact direct-dependency candidates below. Use
`=version` requirements and commit the generated `Cargo.lock` during implementation. Recheck
upstream stable/non-yanked status before the first implementation resolution; adopting a newer
release requires an updated register, lockfile, and affected proof results. No prerelease or
silent downgrade is approved. Record registry checksums and the resolved transitive graph;
this document is not a claim that a lockfile already exists.

**Rationale**: The installed Rust/Cargo 1.93.1 cannot satisfy the observed Rama/Wasmtime minimum
Rust requirements. The [official stable manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml)
is dated 2026-11-12 and selects Rust 1.100.0. Cargo is supplied by that toolchain; the manifest's
internal Cargo version string is not treated as an independently verified Cargo release number.

**Alternatives considered**: installed 1.93.1 (insufficient); floating stable/latest (not
reproducible); prereleases (not authorized); automatically choosing older dependencies (hides
compatibility failures).

| Dependency | Latest stable observed | Declared minimum Rust | License / role | Primary source |
| --- | --- | --- | --- | --- |
| Rama | 0.4.0 | 1.96.0 | MIT OR Apache-2.0; transport adapter | [Registry](https://crates.io/api/v1/crates/rama/0.4.0) |
| Wasmtime | 50.0.2 | 1.97.0 | Apache-2.0 WITH LLVM-exception; component runner | [Registry](https://crates.io/api/v1/crates/wasmtime/50.0.2) |
| wasmtime-wasi | 50.0.2 | 1.97.0 | Apache-2.0 WITH LLVM-exception; matching minimal P2 linker support | [Registry](https://crates.io/api/v1/crates/wasmtime-wasi/50.0.2) |
| wit-bindgen | 0.63.0 | Upstream workspace 1.88.0; registry unspecified | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT; guest bindings | [Registry](https://crates.io/api/v1/crates/wit-bindgen/0.63.0) |
| Tokio | 1.54.1 | 1.85 | MIT; bounded asynchronous I/O | [Registry](https://crates.io/api/v1/crates/tokio/1.54.1) |
| Serde | 1.0.229 | 1.56 | MIT OR Apache-2.0; typed records | [Registry](https://crates.io/api/v1/crates/serde/1.0.229) |
| serde_json | 1.0.154 | 1.71 | MIT OR Apache-2.0; bounded protocol/report encoding | [Registry](https://crates.io/api/v1/crates/serde_json/1.0.154) |
| rustls | 0.23.46 | 1.71 | Apache-2.0 OR ISC OR MIT; explicit client/server trust | [Registry](https://crates.io/api/v1/crates/rustls/0.23.46) |
| rcgen | 0.14.10 | 1.88 | MIT OR Apache-2.0; ephemeral fixture certificates | [Registry](https://crates.io/api/v1/crates/rcgen/0.14.10) |
| uuid | 1.29.3 | 1.89.0 | Apache-2.0 OR MIT; host-generated v4 identifiers | [Registry](https://crates.io/api/v1/crates/uuid/1.29.3) |
| sha2 | 0.11.1 | 1.88 | MIT OR Apache-2.0; immutable artifact digests | [Registry](https://crates.io/api/v1/crates/sha2/0.11.1) |
| rusqlite | 0.43.0 | Registry 1.89.0; upstream supports stable at release | MIT; minimal transactional checkpoint ledger | [Registry](https://crates.io/api/v1/crates/rusqlite/0.43.0) |
| url | 2.5.8 | 1.63 | MIT OR Apache-2.0; URL parsing, not authorization | [Registry](https://crates.io/api/v1/crates/url/2.5.8) |
| ipnet | 2.12.2 | Not declared | MIT OR Apache-2.0; address-range matching | [Registry](https://crates.io/api/v1/crates/ipnet/2.12.2) |
| libc | 0.2.191 | 1.65 | MIT OR Apache-2.0; Linux-only supervised syscall fixtures | [Registry](https://crates.io/api/v1/crates/libc/0.2.191) |
| seccompiler | 0.5.0 | Not declared | Apache-2.0 OR BSD-3-Clause; Linux-only AArch64 seccomp compilation | [Registry](https://crates.io/api/v1/crates/seccompiler/0.5.0) |
| base64 | 0.23.1 | 1.71.0 | MIT OR Apache-2.0; bounded standard padded protocol chunks | [Registry](https://crates.io/api/v1/crates/base64/0.23.1) |
| jiff | 1.0.1 | 1.85 | Unlicense OR MIT; maintained RFC3339 timestamps and civil dates | [Registry](https://crates.io/api/v1/crates/jiff/1.0.1) |
| rustix | 1.1.6 | 1.65 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT; safe host UID and descriptor-relative filesystem operations | [Registry](https://crates.io/api/v1/crates/rustix/1.1.6) |
| subtle | 2.6.1 | Not declared | BSD-3-Clause; maintained constant-time fixture capability equality | [Registry](https://crates.io/api/v1/crates/subtle/2.6.1) |
| hex | 0.4.3 | Not declared | MIT OR Apache-2.0; maintained lowercase digest encoding | [Registry](https://crates.io/api/v1/crates/hex) |
| semver | 1.0.28 | 1.68 | MIT OR Apache-2.0; Cargo requirement matching | [Registry](https://crates.io/api/v1/crates/semver) |
| toml_edit | 0.25.19+spec-1.1.0 | 1.85 | MIT OR Apache-2.0; parse-only Cargo manifests and lockfiles | [Registry](https://crates.io/api/v1/crates/toml_edit) |
| spdx | 0.13.6 | 1.85.0 | Apache-2.0; strict license syntax with historical slash-as-OR only | [Registry](https://crates.io/api/v1/crates/spdx) |

Wasmtime 51.0.0-rc.1 and Rustls 0.24.0-dev.3 were observed prereleases and are not selected.
Rama 0.4.0 is a published non-prerelease, not an older alpha. Its manifest ranges admit the
selected Tokio, Rustls, and rcgen lines; that is manifest evidence, not a successful build.
See the [tagged manifest](https://github.com/plabayo/rama/blob/rama-0.4.0/Cargo.toml).

Select minimal features: Rama `http-backend,tcp,dns,rustls,ring`; Wasmtime with defaults off
and `std,runtime,cranelift,component-model,async`; matching WASI P2 support only as required;
Serde derive; Tokio runtime/time/process/I/O/network/synchronization capabilities actually used.
The guest needs only minimal wit-bindgen binding features, not transport or storage. Keep
one TLS crypto provider. Direct Rustls/rcgen configuration is justified by fixture trust.
Transitive provider/build dependencies are pinned by the actual lockfile, not invented here.

Tauri remains the future desktop shell but is not installed, built, or pinned as an R0 build
dependency. No frontend, model SDK, ORM, cargo-component, or general-purpose web framework is
needed. Review all resolved notices, including LLVM exceptions and guest-image packages,
before distributing any proof bundle; the product's publication license is a separate decision.

The 2026-11-16 refresh confirmed the original stable selections and added exact base64 and
Chrono pins rather than custom wire parsers. Cargo rejected direct time 0.3.55 because Rama
0.4.0 requires exactly 0.3.47; the constrained transitive version remains recorded honestly.
On 2026-11-17, newly issued
[RUSTSEC-2026-0543](https://rustsec.org/advisories/RUSTSEC-2026-0543.html) identified every
Chrono version as unmaintained, without a patched release. Replace that original selection
with maintained Jiff 1.0.1, defaults disabled and `std` enabled, preserving strict public
timestamp/date validation and checked arithmetic. This is not a waiver or approved exception.
The maintainer explicitly chose rejection of leap-second `:60` input on 2026-11-17.
Jiff's normalization must not silently change audit identity or ordering; ordinary UTC,
fraction precision and formatting remain unchanged. Four-digit-year overflow is rejected.

The 2026-11-18 source refresh found the earlier direct selections stale. Select UUID 1.29.3,
matching Wasmtime/WASI 50.0.2, and Jiff 1.0.1 for both host and native Linux code. Jiff 1.0.1
was published during this refresh; its original registry response identifies it as stable,
non-yanked, and Rust-1.85-compatible. Its archive checksum was independently matched.
Jiff 1.0 renames zoned APIs that R0 does not use; the timestamp and civil-date consumers
retain their strict wire contracts. Regenerate lockfiles, source decisions, native preparation,
and affected proof evidence; an older direct pin has no invented approval exception.

Rust 1.100.0, rustfmt, clippy and `wasm32-wasip2` were explicitly installed without changing
the global default. The official matching Linux standard library was subsequently installed
for target-only source checks; native guest execution remains the operational proof.
Use rustix with std/fs/process/time for effective-UID, descriptor-relative no-follow
filesystem operations and native host CPU-clock accounting, not custom host unsafe/libc.
Use the already resolved subtle library for constant-time receiver capability equality,
not a handwritten cryptographic comparison. No additional crypto provider is introduced.

The 2026-11-17 implementation refresh adds the maintained codecs above instead of custom
hexadecimal, Cargo semver/TOML, or SPDX parsers. Original registry responses confirm exact
stable, non-yanked selections; private source captures retain their actual observation times
and downloaded-archive checksums. `toml_edit` disables default features and selects parsing
only. SPDX parsing preserves the original claim and does not choose an alternative license
or grant legal clearance. Host and Linux use the same pinned hex implementation with sha2
0.11's byte-array digest output.

The latest-stable selection rule applies to direct dependencies and selected tools.
Resolved transitive versions are a separate, exact compatibility graph: record upstream
latest observations, selected versions and published constraints without calling an older
transitive release current. Derive direct/transitive classification from the captured Cargo
workspace/resolve graph, not a record's self-declared role. A deliberate older direct/tool
selection still requires explicit reviewed exception evidence. Rama's exact `time` constraint
above is a recorded transitive constraint, not permission for a direct downgrade.

## D-02 — Transport and TLS composition

**Decision**: Use a product-owned transport port with a Rama 0.4.0 adapter and Rustls/ring.
Require four successful laboratory modes: plain HTTP/1.1, CONNECT tunnel, HTTP/1.1 HTTPS
interception, and HTTP/2 over TLS interception with ALPN `h2` on both sides. The H2 fixture
also checks two simultaneous streams and reset containment. No protocol downgrade may be
counted as the required H2 success.

**Rationale**: The retained foundation provides composition primitives, not verified product
support. The [Rustls MITM example](https://github.com/plabayo/rama/blob/rama-0.4.0/examples/src/http_mitm_proxy_rustls.rs)
explicitly lacks a paired CONNECT-to-egress relay, disables upstream verification, forces
upstream HTTP/1.1, tolerates decode errors, and permits key logging. None of those settings
is acceptable evidence. The adapter must implement explicit verified upstream trust,
ALPN/version selection, strict body/error handling, and per-connection scope admission.

For interception, the normalized CONNECT authority, TLS server name, and decrypted request
authority must match; reject authority pivots. If the Rustls path opens a new egress socket,
resolve, check, and pin that socket's actual address before connecting. Tunneling is a distinct
opaque-byte mode, not inspection. Record H2 semantic headers/body, not exact encrypted frames.
Certificate keys stay in host memory; generated roots are loaded only into isolated fixture
client configurations. Never enable key-log environment behavior, skip verification, or
modify OS trust. No LLM call enters forwarding.

**Alternatives considered**: copying the example unchanged (unsafe and not H2 proof);
BoringSSL-based paired relay (upstream's preferred MITM example, but adds a second crypto/build
path unnecessary for this bounded proof); substituting another transport (violates retained
foundation). If the selected composition cannot pass all four modes, R0 fails; do not silently
switch backend or weaken the gate. See [Rama H2 relay regression](https://github.com/plabayo/rama/blob/rama-0.4.0/rama-http-backend/tests/h2_mitm_relay_stream_reset.rs).

## D-03 — Minimal versioned component contract

**Decision**: Use the synchronous `razen:component-proof@0.1.0` WIT world in
[plugin-sdk.wit](contracts/plugin-sdk.wit). Compile a Rust `cdylib` directly to
`wasm32-wasip2` with wit-bindgen; load with Wasmtime Component Model bindings generated from
the same WIT. No component artifact is built during planning.

**Rationale**: The [Rust component guide](https://component-model.bytecodealliance.org/language-support/building-a-simple-component/rust.html)
and [Rust target contract](https://doc.rust-lang.org/rustc/platform-support/wasm32-wasip2.html)
support native component output without cargo-component. Bindings and Wasmtime have independent
version numbering; pin both and the WIT digest. Do not introduce P3 async interfaces into this
P2 proof. Link no environment, filesystem preopens, or networking; expose only the bounded
snapshot reader. WASI linker defaults must remain least-privilege, not inherited host stdio.

Configure linear-memory/table/instance limits, fuel and epochs, independent async host-call
deadlines, bounded results, and supervised runner termination. [Wasmtime interruption](https://docs.wasmtime.dev/examples-interrupting-wasm.html)
does not stop a blocked host call. Global native RSS sampling is a supervisor health check,
not a claimed hard OS allocation cap on macOS; record overshoot and distinguish it from the
hard guest linear-memory ceiling.

The engine shares one aggregate component-invocation slot and one component host-call slot
across all stores/runners, separately from per-Store instance/memory counts. At capacity,
reject immediately with `budget_exhausted` before spawning or effects; do not accumulate a
queue. Release slots on success, trap, timeout and cancellation. CMP-03 and CMP-05 exercise
real overlapping admissions/broker reads, while CMP-07 requires a fresh successful invocation
after each variant. The synchronous WIT world needs no new async guest import for this host
resource policy.

Actual native startup exposed that the original one-instance/one-table policy rejected the
public WASI P2 fixture before analysis. The maintainer approved policy profile `0.2.0` with
three core Wasm instances and two tables per Store, keeping one memory, 64 MiB and both
engine-wide concurrency caps unchanged. All six fixtures reached startup under these caps;
that diagnostic was not a completed broker/evidence proof. Native allocation probes now
instantiate real memory/table modules through the configured limits and attempt exactly
`limit + 1` allocations; host-created handles alone do not test guest module counts.
Historical `0.1.0` profiles retain their original ceilings.

**Alternatives considered**: core-module-only ABI, preview1 adaptation, cargo-component,
arbitrary guest networking, or a production SDK/plugin manager (unnecessary or out of scope).

## D-04 — Enforceable external-process backend

**Decision**: Select Lima 2.3.0 with native VZ, a dedicated plain-mode Debian arm64 VM, and
bubblewrap 0.13.1 plus seccomp and cgroup-v2 limits for each workload. Workload code runs as a
separate no-sudo UID. The trusted guest supervisor alone controls cgroups. Only bounded stdio
pipes cross the workload boundary; all target/model effects are brokered by the macOS host.

**Rationale**: [Lima plain mode](https://lima-vm.io/docs/config/plain/) removes convenience
mounts, dynamic forwarding, guest agent, and containerd, but static forwarding still works.
Inspect effective configuration, including global defaults/overrides. Use a private owned
`LIMA_HOME`, empty host mounts/static forwards/socket forwards, no agent/X11 forwarding,
no Rosetta, and no proxy/credential inheritance. Lima networking is not the security policy:
the child must have mandatory fresh namespaces and a syscall policy denying socket creation,
including AF_VSOCK. Do not run hostile code as Lima's management user with passwordless sudo.

The guest supervisor places the launcher in its final cgroup before releasing untrusted code.
Require available memory/CPU/PID controllers; hide the management filesystem and cgroup controls.
Use mandatory user/mount/PID/IPC/UTS/network/cgroup namespaces, capabilities dropped, cleared
environment, read-only approved runtime/input mounts, a bounded tmpfs, and no inherited socket
or secret descriptors. Do not treat `--unshare-all` with `*-try` behavior as proof of a mandatory
namespace. The AArch64 seccomp allowlist must cover permitted fork/exec while rejecting
privilege/namespace/cgroup escape, ptrace, mount, BPF, io_uring, and all direct socket families.
Compile the reviewed AArch64 syscall allowlist with the pinned seccompiler library and pass
the resulting filter through bubblewrap's seccomp descriptor; do not handwrite BPF opcodes.
Linux-only libc calls are confined to the trusted launcher/actual syscall adversary fixtures,
not portable domain code. The management process must remain outside the workload filter.

On cancellation the host installs and acknowledges the revision barrier first, independently
of guest response. Then the supervisor kills the invocation cgroup and verifies it is empty;
if control is lost, force-stop the dedicated VM. An independent guest lease/watchdog terminates
orphaned work after host/transport loss. Killing an SSH client alone does not prove that remote
children died. See [cgroup-v2](https://docs.kernel.org/admin-guide/cgroup-v2.html),
[systemd delegation](https://systemd.io/CGROUP_DELEGATION/),
[bubblewrap policy limitations](https://github.com/containers/bubblewrap/blob/v0.13.1/README.md),
and [Lima stop](https://lima-vm.io/docs/reference/limactl_stop/).

**Reproducible provisioning selection**:

- [Lima 2.3.0 release](https://github.com/lima-vm/lima/releases/tag/v2.3.0), published 2026-11-06.
  Its exact Darwin-arm64 archive is
  `https://github.com/lima-vm/lima/releases/download/v2.3.0/lima-2.3.0-Darwin-arm64.tar.gz`,
  published SHA-256 `b7af444bd8f91d3c307477e562f2cf3bd7595d62b9429185e4fa841563578cfc`.
  The release publishes `SHA256SUMS.asc`; signature authenticity has not been verified.
  Install the complete verified bundle in a new private versioned prefix, not over Homebrew.
- [bubblewrap 0.13.1](https://github.com/containers/bubblewrap/releases/tag/v0.13.1), published
  2026-10-14; source tarball SHA-256
  `0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d`.
  Do not silently use an older distribution package.
- Debian stable 13.7; dated cloud build `20261111-2659`. Select the raw arm64 image to avoid
  an unverified qemu-img installation/conversion dependency:
  `https://cloud.debian.org/images/cloud/trixie/20261111-2659/debian-13-genericcloud-arm64-20261111-2659.raw`.
  Published SHA-512:
  `255ed35957114b453d72cf021f70542d09dccbb9210640a220a4d0931fa80e1ea956785a7ca88b33d58b55dd4d00f0677b0016a14c99a168b6ed8e239ac98b09`.
  Source: [official checksum manifest](https://cloud.debian.org/images/cloud/trixie/20261111-2659/SHA512SUMS).
  Initial research observed the published checksum only. Explicit 2026-11-17 preparation
  subsequently verified the downloaded raw-image cache against this exact SHA-512 pin.
  No detached image-manifest signature authenticity is claimed.
- Provision dependencies only during an explicit, network-enabled preparation phase. Record
  the final guest package manifest, image digest, kernel, supervisor, seccomp policy, scripts,
  and built-binary hashes. Workload execution is offline and never mounts the repository.
  Pin provisioning contents themselves: Lima's provision `file.digest` is not verification.

**Alternatives considered**: deprecated/unsupported custom sandbox-exec profiles; App Sandbox
(useful signed-app isolation but not a simpler per-invocation descendant/resource proof here);
Apple container (valid VM alternative but adds another manager); Docker/default Lima settings
(implicit mounts, sockets, network, and management authority are not an acceptable policy).
Lima is Apache-2.0. Preserve bubblewrap's LGPL source/package notices and Debian package
licenses; do not describe the guest image as having a single permissive license.

## D-05 — Durable proof ledger and recovery semantics

**Decision**: Use a single-writer SQLite ledger via bundled rusqlite. Select rollback journal,
`synchronous=FULL`, `fullfsync=ON` on macOS, foreign-key enforcement, and a bounded busy timeout.
Rusqlite 0.43.0 documents bundled SQLite 3.54.1 through libsqlite3-sys 0.40.0; verify the actual
resolved bundle at build time. See its [published README](https://crates.io/api/v1/crates/rusqlite/0.43.0/readme)
and [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html).

**Rationale**: Atomically persist reservation, invocation/attempt state, control revision, and
event/outbox references before admitting an effect. A crash after `sending` is recorded may
leave an unknown external outcome even if no bytes arrived; never infer safe retry from a
missing response. A controlled receiver survives host SIGKILL and records actual effects.
Restart reconciles the saved ledger and current policy, not a replay of prior commands.

The ledger is fixture-only, with private filesystem permissions and redacted metadata. It is
not a production project database or a full-encryption implementation. Do not ingest real
traffic/private code/credentials. CA keys are never persisted. This choice does not weaken
the constitution's protection requirements for future sensitive project data.

**Alternatives considered**: memory-only restored fixtures (rejected by clarification);
handwritten append-log/atomic JSON checkpoint (unnecessary crash/transaction complexity);
production storage/ORM/encryption backend (outside R0). SQLite atomicity does not imply
exactly-once network execution or immunity to broken storage hardware.

## D-06 — Pilot, limits, and measurement

**Decision**: Use the versioned [pilot profile](contracts/pilot-profile.json) as the authoritative
limit set. The pilot is macOS 26.5.1 arm64 with at least four available logical cores and
16 GiB RAM; the observed host has 12 logical CPUs and 24 GiB RAM. Give the VM two CPUs and
2 GiB RAM, leaving host supervision separate from workload cgroups. Capture hardware model,
OS/kernel, storage/filesystem, versions, fixture digests, and actual limits in every run.

**Rationale**: Hard acceptance concerns control acknowledgment, correct denial/containment,
and durable no-resend behavior. The profile also fixes practical bounded sizes, queues,
wall-clock deadlines, and cleanup observations before any measurement. Those limits are R0
fixture budgets, not claimed product performance. Do not compile or provision while timing.
Measure direct/proxy latency and resource usage; do not require the R1 full search/load journey.
Only Rust and JavaScript/TypeScript are selected as initial source-language families; R0
records this boundary and does not build language analyzers.

**Alternatives considered**: unspecified/unbounded limits; treating proposed product p95
thresholds as already achieved; native external macOS tools, GUI/browser workloads, and
multiple-OS acceptance before a pilot exists.

## D-07 — Evidence, interfaces, and execution order

**Decision**: Keep a small Rust host proof package, a separate component fixture package, and
a Linux supervisor/adversary fixture package. Share the product-owned domain contract, not
Rama/Wasmtime/storage objects. Use strict versioned JSON Lines for runtime/host messages and
a synchronous WIT component boundary. The host alone derives identity and authority.

R0-01's definitions must be agreed before the independent transport, component, and runtime
proofs. R0-05 aggregates all mandatory cases; it may prepare tooling early but cannot pass
before their evidence exists. The [verification matrix](contracts/verification-matrix.md)
and [CLI contract](contracts/proof-cli.md) define the execution manifest and honest exit status.

Common execution records, including ControlMeasurement, belong to US1 before its parser/ledger
consumers. US1 also supplies the independently serviced host control loop and durable revision
barrier; US3 measures this same handler under component saturation without a hidden US4
dependency. US4 reuses it for runtime lifecycle routing and recovery. Required provider/module
wiring precedes passing integration tests. The clean-checkout guide builds all approved
component variants and host binaries, prepares the pinned guest explicitly, and only then
runs dependent all-target/workspace checks. Historical grant references and peer correlation
IDs remain provenance, never authority; their precise state/namespace validation is specified
in [data-model.md](data-model.md).

**Rationale**: This is enough separation to test real boundaries without constructing the
baseline's entire future application. Four graph/trace contracts remain distinct, local memory
has exactly two levels, and unsupported capabilities stay unavailable. No R1–R5 spec, task
list, frontend, live model, production SDK, or application source is generated by this command.

**Alternatives considered**: a crate for every future module; a framework-owned state store;
returning empty success on error; counting negative outcomes as a required positive mode;
calling configuration inspection a successful isolation proof.

## D-08 — Bounded deterministic parser fuzzing

**Decision**: Extend CON-02 with stable-Rust seeded mutation fuzzing of checked-in valid/invalid
byte corpora, invoking the actual framing codec and typed contract parser. Reuse a small test
helper in `crates/engine/tests/support/parser_mutation.rs`, a versioned corpus manifest under
`fixtures/scenarios/parser-corpus/`, and the `parser_fuzz` block of the canonical profile.
Foundation framing tests and `crates/engine/tests/us1_parser_fuzz.rs` own the corresponding
oracles; the latter also validates typed record/grant/ID invariants. No fuzzing framework,
nightly toolchain, or additional dependency is required.

**Rationale**: Selected malformed examples alone do not meet the constitution's parser-fuzzing
gate. Deterministic byte insertion/deletion/replacement and corpus splicing use the recorded
seed/generator version, finite input count/size and aggregate deadline. A pass requires the
configured input budget, valid-record round-trip/invariant checks and explicit rejection of
invalid inputs, not a bare no-panic assertion. Record corpus digest, seed, mutation version,
input count, limits and replayable counterexamples; a panic, timeout, truncated budget or
missing evidence fails the proof rather than silently reducing coverage. Reuse bounded
buffers rather than retaining every mutated input.

**Alternatives considered**: a few hardcoded invalid samples (insufficient); an unbounded
random loop (not reproducible); a new nightly/libFuzzer toolchain (unnecessary for this bounded
R0 boundary). Broader fuzz campaigns can be added later without weakening this required proof.

## Research disposition

All planning choices above are resolved. No policy exception is approved. The pinned Rust
1.100.0 toolchain and private Lima 2.3.0 bundle are explicitly installed; no default Lima,
Homebrew installation, Docker service, or global default toolchain was substituted. All three
Cargo graphs and original source archives are captured. Actual Linux-target typechecking
and a native guest release build succeeded. Guest preparation remains fail-closed until
its active privilege checks and remaining setup complete; controller/namespace/descendant
isolation, full transport/component/runtime proofs, timings, forced restart and maintainer
acceptance remain mandatory execution gates, not inferred passes.
