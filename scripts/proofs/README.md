# R0 proof preparation and operations

Scope: only the fixture-driven R0 feasibility slice. The authoritative interfaces and complete
validation order are in [the feature quickstart](../../specs/001-r0-feasibility/quickstart.md),
[CLI contract](../../specs/001-r0-feasibility/contracts/proof-cli.md), and
[verification inventory](../../specs/001-r0-feasibility/contracts/verification-matrix.md).
A passing selected suite is not a complete R0 exit or maintainer approval.

## Toolchains and workspaces

The host workspace uses the exact toolchain in `rust-toolchain.toml`. The component and Linux
fixture packages are independent workspaces and must retain their own reviewed `Cargo.lock`.
Never add their incompatible targets to the host workspace or silently update a lockfile.

Explicit toolchain provisioning (performed during implementation, not by proof commands):

```sh
rustup toolchain install 1.100.0 --profile minimal --component rustfmt --component clippy \
  --target wasm32-wasip2
```

Initial deliberate lockfile resolution, after reviewing exact manifest pins:

```sh
cargo +1.100.0 generate-lockfile
cargo +1.100.0 generate-lockfile --manifest-path fixtures/components/Cargo.toml
cargo +1.100.0 generate-lockfile --manifest-path fixtures/linux-runner/Cargo.toml
```

Review registry checksums, MSRVs, licenses and the feature graph. Use `--locked` for subsequent
fetch/build/test commands. Linux binaries are compiled natively inside explicit guest
preparation, never as Darwin host targets. Component builds use only `wasm32-wasip2` and the
public pinned WIT; each mutually exclusive variant must produce its own hashed artifact.

## Network-enabled preparation versus offline proofs

Only deliberate development dependency fetches and `prepare-isolation --confirm-provision`
may download packages. Ordinary `doctor`, `run`, `verify`, tests and timed measurements must
not fetch, compile, provision, upgrade tools or repair an unavailable backend automatically.
Prepared workload execution is offline; every target/model effect must cross host admission.

Use the exact Lima 2.3.0 Darwin-arm64 archive and published SHA-256 in the research register.
Verify downloaded bytes before extraction into a new private versioned prefix under
`target/r0-tools/lima/2.3.0`; retain the complete bundle and notices. Invoke its absolute
`bin/limactl` path rather than overwriting Homebrew or changing the user's default Lima.
Preserve checksum/signature provenance; downloading a detached signature is not verification
of its signer. No Gatekeeper changes, OS trust changes, Rosetta or implicit host sudo.

The VM must use a short, private, explicitly owned `LIMA_HOME`, never `~/.lima`. Reject
unrelated existing directories and symlinks. Use only the dedicated `razen-r0` instance and
inspect effective merged configuration, including defaults/overrides. Require VZ/plain,
verified raw image, no repository/home mounts, no forwards/agents/manager sockets, and no
proxy/credential inheritance. Record image, package, provisioning, namespace, cgroup,
seccomp and binary digests; missing primitives block launch rather than select a fallback.

Keep private control capabilities, VM state and generated proof artifacts outside committed
source. Only owned run resources may be cleaned; preserve redacted evidence and checkpoints.
Do not delete unrelated VMs, files or staging state.

## Current implementation evidence

The pinned Rust toolchain, rustfmt/clippy and WASI P2 standard library have been explicitly
installed. Initial Cargo resolution exposed Rama's exact transitive `time = 0.3.47`
constraint; the rejected latest `time` candidate remains recorded. Direct RFC3339 handling
uses the maintained codec documented below, without a downgrade or backend substitution.

Observed: host binaries and all six public-WIT variants build. The pinned guest builds
natively; native formatting, strict all-target Clippy and all seven fixture tests pass.
The launcher regression retains real `EPERM` metadata across a separate actual cleanup
failure. Signed source facts cover all 388 installed packages and live private configuration
validation succeeds. The current coherent `target/r0-evidence/final-r0/` packet passes all
35 mandatory cases; its full-source prerequisites are retained under
`target/r0-evidence/final-checks/validation-inputs-canonical-binding.json`.
Explicit maintainer approval remains pending; passing proofs do not set `r0_exit_ready`.

Full-run history has separate finite artifact and enclosing packet bounds. Snapshot/proposal
limits, metadata/total-byte limits and identity/hash checks are not waived to fit a run.
See the quickstart's [recovery limits](../../specs/001-r0-feasibility/quickstart.md#recovery-and-safe-rollback).

The current maintained date codec is Jiff 1.0.1. Chrono was removed after newly issued
RUSTSEC-2026-0543 marked all versions unmaintained. UTC inputs reject leap seconds explicitly
under the maintainer's recorded policy; no normalization or advisory waiver is inferred.
See [distribution findings](../../docs/r0-distribution.md) for exact source/advisory/notice
evidence and separate publication gates.

Failed explicit preparation must be retired through selected-run
`razen-proof cleanup --run OUT --stop-isolation` before changing pinned native/script sources.
Retirement preserves original evidence, verified image bytes and the shared capacity inode;
it never adopts a replacement process or starts/deletes an unrelated VM.
