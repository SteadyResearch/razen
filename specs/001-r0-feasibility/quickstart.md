# R0 Quickstart and Validation Guide

## Status and safety

On 2026-11-18 the current R0 source passed 508 workspace tests, seven guest-native tests,
strict formatting/Clippy, both complete 10,000-input parser campaigns and all 35 mandatory
proof cases. The coherent packet is `target/r0-evidence/final-r0/`, run
`5f3e5ddc-e1d1-442d-bdc5-2ed688e14003`; no selected-suite evidence was merged into it.

Both the full proof command and read-only verification exited 0. That confirms the proofs,
not maintainer approval: `review.json` is explicitly pending, `review_status` is `unreviewed`,
and `r0_exit_ready` remains false. See [proof-cli.md](contracts/proof-cli.md) and
[verification-matrix.md](contracts/verification-matrix.md). These are controlled R0
feasibility observations, not production, broader-platform or later-phase delivery claims.

**Current specification boundary:** Constitution 1.1.0 and general specification content
version 0.2 retain Tauri and add independent local/remote product deployment in R1
(FUN-95, CA-81/CA-82). These R0 results do not verify that product API or service lifecycle.
See [Baseline Amendment Scope](spec.md#baseline-amendment-scope); this guide does not install
a frontend, expose a remote product endpoint, or reclassify the Linux isolation fixture as
a production backend.

Only controlled fixture systems are authorized. Never install a test CA in OS trust, use
`curl -k`/disabled certificate verification, expose a public listener, execute repository hooks,
mount the home directory into a workload, or give a workload SSH/container-manager sockets.
No live model, real credential, production target, or confidential repository is required.

## Prerequisites

1. Work from the repository root on the selected macOS arm64 pilot and meet
   [pilot-profile.json](contracts/pilot-profile.json). Keep the dependency register from
   [research.md](research.md) with the implemented sources, fixture hashes, and actual lockfile.
2. Use the selected Rust 1.100.0 toolchain and private Lima 2.3.0 bundle. The originally
   observed global Rust 1.93.1 and Lima 2.1.1 are not selected backends. Install exact reviewed
   versions explicitly without replacing those shared installations or choosing prereleases.
3. Use the reviewed exact manifest requirements and three independent lockfiles. Explicitly
   prepare the pinned raw image and bubblewrap source under a private `LIMA_HOME`; archive
   actual package, seccomp, provisioning, binary and effective-configuration hashes.
   Do not regenerate lockfiles or mount the repository/home during an ordinary proof run.
4. Provisioning is an explicitly authorized setup action, separate from opening source or
   running tests. It may fetch approved toolchains/packages; actual proof execution must not.
   Inspect all manifests/licenses. No auto-install/upgrade or host administrator password is
   part of the normal fixture run.

The explicit toolchain setup target is:

```sh
rustup toolchain install 1.100.0 --profile minimal --component rustfmt --component clippy
rustup target add --toolchain 1.100.0 wasm32-wasip2
rustc +1.100.0 --version
target/r0-tools/lima/2.3.0/bin/limactl --version
```

The Lima version must match the register; install/upgrade it deliberately from the reviewed
upstream release before continuing. Do not create a VM with unreviewed default mounts or
forwarding. The committed `rust-toolchain.toml` selects the workspace toolchain without
changing the user's global default.

## Contracts-only checkpoint

This increment requires the pinned host toolchain/dependencies, not a component or VM.
Fetch dependencies explicitly during setup if they are not already cached, then:

```sh
cargo build --offline --locked -p razen-engine --bins
OUT="target/r0-evidence/us1-contracts/run-$(/usr/bin/uuidgen | tr '[:upper:]' '[:lower:]')"
cargo run --offline --locked -p razen-engine --bin razen-proof -- run \
  --profile specs/001-r0-feasibility/contracts/pilot-profile.json \
  --suite contracts --out "$OUT"
cargo run --offline --locked -p razen-engine --bin razen-proof -- cleanup --run "$OUT"
cargo run --offline --locked -p razen-engine --bin razen-proof -- verify --run "$OUT"
```

Observed: run/cleanup exit 0; verification after cleanup exits 4 (`incomplete`), with
5 passed and 30 unexecuted cases, `review_status = unreviewed`, and `r0_exit_ready = false`.
Both parser targets execute their complete 10,000-input campaigns. Cleanup preserves
immutable metadata, evidence, replay sources, and the ledger. Use a fresh child run:
the parent directory also contains retained typed-fuzz evidence and must not be adopted.

## Build proof prerequisites

Build approved component variants and host binaries before checks that load those artifacts:

```sh
cargo +1.100.0 fetch --locked
cargo +1.100.0 fetch --manifest-path fixtures/components/Cargo.toml --locked
scripts/proofs/build-components.sh
cargo +1.100.0 build --workspace --bins --locked
```

The helper builds every reviewed mutually exclusive variant with the pinned WASI P2
target/lockfile, writes distinct hashed outputs and
`target/proof-components/build-manifest.json`, and fails if a variant is missing. Six distinct
variants have been built. This is an explicit setup step, never an ordinary proof-run effect;
a default component build does not supply all adversarial fixtures.

The Linux supervisor/adversary workspace is compiled natively during explicit pinned guest
preparation; no unverified cross-linker is required. The official matching Linux Rust standard
library also permits target-only checks without claiming native execution. Both fixture
workspaces retain independent reviewed lockfiles and are excluded from host targets. Native
`wasm32-wasip2` output is already a component; do not add cargo-component or adapt a core module.

## Prepare isolated runner

After approved source/fixtures are implemented and pinned:

```sh
target/debug/razen-proof prepare-isolation \
  --profile specs/001-r0-feasibility/contracts/pilot-profile.json \
  --confirm-provision --out target/r0-preparation
target/debug/razen-proof doctor \
  --profile specs/001-r0-feasibility/contracts/pilot-profile.json
```

Observed: the pinned VZ/plain VM prepares and compiles its Linux fixtures natively, with no
mounts/forwards/agent credentials and a distinct no-sudo workload UID. Mandatory primitives
and clean effective configuration are checked before launch; each invocation supplies its
own attestation. Missing or contaminated state returns exit 3 and a blocked report, not a
native-process/container fallback. Preparation is never implicit in opening a plan or tests.

A failed preparation remains sealed. Before changing native/provisioning sources or preparing
a fresh owner, explicitly retire the selected failed output:

```sh
target/debug/razen-proof cleanup --run target/r0-preparation --stop-isolation
```

Cleanup authenticates the original resource/process and stopped receipt; it preserves original
evidence, the capacity-lock inode and verified image cache. Never delete lock/owner markers,
adopt a different PID, restart a retired VM, or use the default Lima home as a shortcut.

A successful preparation remains bound to its original source, owner and process-birth
receipts. Stopping its VM is not a restart or source-migration command. Preserve those
receipts; never rewrite their hashes or substitute a new process for the frozen owner.

Debug/test builds optimize the `sha2` dependency for full streaming image-integrity checks.
They do not cache away those checks, change the original pins, or extend worker/lease/control
deadlines. The real owned-engine orphan proof passes with the unchanged startup barrier.

Explicit source preparation also supplies private
`target/r0-evidence/preparation/provenance/inputs.json` using the collector's bounded schema
in `crates/engine/src/application/provenance.rs`. Retain original unfiltered
`cargo metadata --offline --locked --format-version 1` output for all three workspaces, exact
lock digests, original registry/latest-version responses and verified source archives. Bind
the actual Rust/isolation observations and every exported installed-package copyright,
policy, metadata, maintained-APT facts and corresponding real repository URI. Keep directories
0700 and inputs/raw captures 0600. Recorded source decisions are not invented approvals.
Ordinary collection/doctor/run/verify must not fetch, compile, provision or repair those inputs.

## Run local and integration checks

After component/host builds and successful explicit guest preparation/preflight, run the
native fixture checks through the prepared guest's standalone pinned Cargo, not Darwin Cargo
or a rustup `+toolchain` argument:

```sh
r0_guest_cargo() {
  LIMA_HOME="$(jq -r '.lima_home' target/r0-guest/prepared.json)" \
    target/r0-tools/lima/2.3.0/bin/limactl --tty=false \
      shell --start=false --preserve-env=false --workdir=/ razen-r0 \
      sudo -n env \
        PATH=/opt/razen/rust-1.100.0/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        CARGO_HOME=/var/lib/razen/build/cargo-home cargo "$@"
}
NATIVE_MANIFEST=/var/lib/razen/build/source/fixtures/linux-runner/Cargo.toml
r0_guest_cargo fmt --manifest-path "$NATIVE_MANIFEST" --all -- --check
r0_guest_cargo clippy --manifest-path "$NATIVE_MANIFEST" --all-targets --offline --locked -- -D warnings
r0_guest_cargo test --manifest-path "$NATIVE_MANIFEST" --all-targets --no-fail-fast \
  --offline --locked -- --test-threads=1
```

Observed on the reviewed launcher source: native formatting, strict all-target Clippy and all
seven native tests pass, including real launcher `EPERM` retention across a separate actual
cleanup failure. Then run the host checks:

```sh
cargo +1.100.0 fmt --all -- --check
cargo +1.100.0 clippy --workspace --all-targets --offline --locked -- -D warnings
cargo +1.100.0 test --workspace --all-targets --no-fail-fast --offline --locked -- --test-threads=1
```

The workspace run includes deterministic framing fuzzing in `foundation_protocol` and typed
parser fuzzing in `us1_parser_fuzz`. Each uses the profile's `parser_fuzz` budget and records
seed, mutation version, corpus digest, executed count and replayable failures. A pass requires
valid-record round-trip/invariant checks and explicit malformed-input rejection, not bare
not-throw/source-text checks. A timeout, incomplete input budget or missing fixture/backend
is failed/blocked evidence, never an ignored/skipped success. No component compilation or
VM provisioning is performed by these dependent tests or timed proof runs.

## Run the required proof inventory

Use a fresh owned run directory; retain all engine/receiver/control observations under it:

```sh
OUT="target/r0-evidence/full-$(/usr/bin/uuidgen | tr '[:upper:]' '[:lower:]')"
target/debug/razen-proof run \
  --profile specs/001-r0-feasibility/contracts/pilot-profile.json \
  --suite all --out "$OUT"
target/debug/razen-proof verify --run "$OUT"
```

Expected observations, not merely exit-code checks:

- **Contracts**: CON cases reject invalid/foreign/stale authority and preserve valid evidence.
  CON-02 includes the complete deterministic parser fuzz budget and replayable corpus evidence.
  Preauthorization records omit grants; authorized states require them; cancellation preserves
  assignment history. Entity/catalog/peer identifiers use their own namespace rules. The two
  consumers still share host admission and local memory remains user/session only.
- **Transport**: NET-01 through NET-04 successfully forward all four required modes. NET-04
  proves H2 on both legs, not a downgrade. NET-05 through NET-08 prove denial, verified TLS,
  unchanged OS trust, bounded/error behavior, and reset containment with receiver observations.
- **Components**: CMP cases use only the public WIT and exercise aggregate invocation and
  host-call saturation separately from per-Store limits. Excess work gets `budget_exhausted`
  without effects/queue growth; success/trap/timeout/cancellation release slots. After every
  adversarial variant, a fresh valid invocation succeeds and control remains responsive.
- **Runtime/processes**: RUN cases attempt actual forbidden reads/sockets/escapes, including
  descendants and AF_VSOCK; guests cannot reach targets/models except through granted host
  calls. RUN-06 records all ten control samples meeting the profile deadline and zero stale
  admissions, including a runtime that blocks or ignores cancellation.
- **Recovery**: REC cases SIGKILL the real owned engine around durable admission/receiver/
  completion barriers while the independent receiver stays alive. Saved consumption and
  current grants survive; receiver counters show no automatic uncertain-action resend.
- **Exit**: EXIT cases record exact versions, profile, raw results, decisions, and limitations.
  `verify` checks all mandatory cases/evidence; a selected-suite pass is not a complete R0 pass.
  Maintainer approval is recorded separately and never inferred from a successful command.

For a narrow rerun during implementation, `run --suite transport --case NET-04` is allowed,
but it produces a partial run and cannot replace the full reviewed inventory. Do not combine
results from incompatible version/profile/fixture sets to fabricate a passing aggregate.

## Recovery and safe rollback

Use `run --suite recovery --out FRESH_PATH` for the five actual owned-engine SIGKILL seams;
the independent receiver remains alive while the engine restarts from its durable ledger.
Keep the original checkpoint/outbox, consumed budget and immutable evidence. Never repair a
failed proof by editing ledger JSON, resetting quota or automatically resending an
`outcome_unknown` action. A recovery-only packet is still partial R0 evidence.

History remains finite: 16,384 canonical events and paired checkpoints, 8,192 artifact records,
4,096 snapshots and 4,096 proposals. The enclosing packet permits 16,384 files/directories,
512 MiB total bytes and 4 MiB per published metadata document. These counts cover separate
artifact bodies, catalog records and recovery files; they are not per-case truncation limits.
Exhaustion fails closed. Never prune committed evidence or reset quota to fit a packet.

If preflight or a required primitive fails, retain the blocked/error packet and clean only
its owned resources. Restore the reviewed source/tool/configuration through explicit setup;
do not disable verification, adopt another VM/process, or silently select a different backend.

## Review and cleanup

Review the redacted packet, version/license register, expected-vs-observed outcomes, control
measurements, receiver counters, descendant termination, and all blockers. A negative test
passes only when an attempted forbidden operation is demonstrably denied, not when the
receiver is absent. Any mandatory failure/blocked/unexecuted case prevents a passing exit.

```sh
target/debug/razen-proof cleanup --run "$OUT" --stop-isolation
```

Expected: owned workers/guest execution stop, temporary client trust and inputs are removed,
OS trust remains unchanged, and redacted evidence/checkpoints remain available for review.
Do not automatically delete unrelated files, VMs, or source. Passing R0 permits a separate
R1 specification/estimate decision; it does not deliver R1 or authorize further target testing.

Observed final cleanup on 2026-11-18: `cleanup --stop-isolation` exited 0 after the owned
guest was observed stopped; read-only verification afterward exited 0 with all 35 cases
still passed. User, admin and system trust-setting bytes AND command exit codes exactly
match the retained pre-proof baseline. Evidence and checkpoints remain intact.
The command outputs and private trust comparison are retained under
`target/r0-evidence/final-checks/final-r0-cleanup-stop.stdout.json`,
`target/r0-evidence/final-checks/final-r0-after-cleanup-verify.stdout.json`, and
`target/r0-evidence/final-checks/os-trust-after-final-r0/comparison.txt`.
The frozen preparation receipt now describes a stopped owned guest; do not adopt a new
process or restart it under that old identity. Follow the explicit retirement/preparation
procedure before any new live proof requiring a fresh backend.
