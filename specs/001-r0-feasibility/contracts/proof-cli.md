# R0 Proof Harness CLI

**Status**: The bounded host CLI, proof suites, actual Wasmtime component paths and native
isolation interfaces are implemented. Explicit current-source guest preparation and read-only
`doctor` pass with the prepared authoritative captures. Build host/component artifacts and
prepare the approved backend before proof execution. Full 35-case validation and an explicit
exact-manifest maintainer decision remain required; interface availability or selected-suite
success is not a passing R0 exit.

This is a bounded laboratory harness, not the product's general-purpose CLI. Related:
[profile](pilot-profile.json), [verification inventory](verification-matrix.md),
[engine protocol](engine-protocol.md), [data model](../data-model.md).

## Entry points

Host package/binary: `cargo run --offline --locked -p razen-engine --bin razen-proof -- <command>`.
Run from the repository root. All filesystem arguments resolve beneath an explicitly selected
owned proof workspace or the repository's reviewed fixture/profile files; reject path traversal,
unsafe symlinks, an existing unrelated output directory, and arbitrary program/shell arguments.

| Command | Arguments | Behavior |
| --- | --- | --- |
| `doctor` | `--profile PATH`, optional `--out PATH` | Read-only checks of exact toolchain/manager versions, host resources, pinned fixture/provisioning manifests, effective VM config and available backend; records blocked prerequisites rather than launching work |
| `prepare-isolation` | `--profile PATH --confirm-provision`, `--out PATH` | Explicitly provision the dedicated pinned VM and approved fixture binaries; this is the only VM/bootstrap phase allowed to download packages; no host trust changes or implicit sudo |
| `run` | `--profile PATH --suite NAME --out PATH`, optional `--case ID` | Execute selected cases against fixture targets; NAME is `contracts`, `transport`, `components`, `runtime`, `recovery`, `exit`, or `all`; no network dependency fetch or real provider access |
| `verify` | `--run PATH` | Recompute evidence integrity and required coverage, validate versions/profile/limits/outcomes, and report whether the full R0 exit passes; selected-case success is not full completion |
| `cleanup` | `--run PATH`, optional `--stop-isolation` | Remove only owned ephemeral trust/input/output material and stop owned workers; optionally stop the dedicated VM; preserve the redacted evidence packet and ledger needed for review |

`doctor` may report missing setup before preparation; it must not convert absent VM/controller
information into a pass. Dependencies are refreshed through deliberate development/toolchain
provisioning, not an automatic effect of any normal command. A changed resolved version set
requires updating the register/pins and rerunning affected evidence, not executing floating latest.

## Output and status

- Stdout: exactly one final UTF-8 JSON summary object containing `protocol`, `command`,
  `status`, optional `run_ref`, `counts`, `review_status`, `r0_exit_ready`, and `error_refs[]`.
  No progress chatter or raw target bodies on stdout; stderr is bounded and redacted.
- `counts` contains nonnegative `total`, `passed`, `failed`, `blocked`, and `unexecuted`;
  the four outcome counts sum to total and agree with unique ProofResult records.
- `status`: `passed`, `failed`, `blocked`, or `incomplete`, describing the command/proof gate.
  `review_status`: `unreviewed`, `approved`, or `rejected`, never inferred from proof success.
  `r0_exit_ready` is true only when every mandatory case passed AND the maintainer approved
  that exact run/profile/version manifest. A selected-suite pass is never full R0 readiness.
  `verify` evaluates the full inventory; it may report passing proofs with readiness false
  while review is pending. Commands without a run report unreviewed and readiness false.
- Exit codes: `0` all requirements of that command satisfied; `1` observed proof/verification
  failure; `2` invalid input/contract; `3` blocked prerequisite/isolation/version; `4` incomplete
  evidence/cancelled execution. Never report a skipped mandatory proof as success.
- Unknown options, suite/case IDs, or contract/profile versions are errors, not ignored flags.

## Evidence layout

All paths are under the owned `--out` run directory, created with private permissions:

```text
run.json                  identity, environment, profile and version/fixture digests
profile.json              exact immutable profile used
versions.json             observed/selected versions, provenance, build and image hashes
cases.json                full required case manifest and selected subset
fixture-manifest.json     exact original scenario manifest, separate from selected cases
results.json              one ProofResult per case, including unexecuted cases
trace.jsonl               redacted attributed events with causality/revisions
evidence/                 bounded immutable artifacts, receiver counts, control measurements
ledger.sqlite             minimal transactional checkpoint; synthetic data only
exit.json                 aggregate decision, mandatory counts, limitations, reviewer status
manifest.json             immutable coverage, ownership, lengths and SHA-256 file seals
```

`run.json`, `profile.json`, `versions.json`, `cases.json`, result/evidence references, and hashes
must agree. Duplicate case IDs or missing/modified required evidence make verification fail.
`exit.json` reports the deterministic proof-gate result separately from a maintainer's approval.
An explicit `review.json` DecisionRecord identifies the reviewer, disposition, review time,
and immutable manifest/evidence references for the exact run. Missing/stale approval leaves
readiness false; it must not be fabricated. The local owner's audit log is not tamper-proof.

Never include CA private keys, management credentials, local control capabilities, full real
bodies, home-directory paths, or unredacted fixture-secret markers in the review/export packet.
A failed run still emits the bounded diagnostics and partial evidence available; writing failure
must be visible. Do not create an apparently valid empty packet when disk integrity fails.

## Cancellation and restart

`run` starts a trusted orchestration process, a separate engine, and independent controlled
receivers as needed. Control receipt/active-barrier acknowledgment are measured in the engine's
clock epoch. The orchestrator never kills arbitrary PIDs: crash seams identify owned child
processes only. Receiver processes survive engine SIGKILL, not an entire machine reboot.

A host interrupt requests the control barrier before stopping workers, records sent/unknown
outcomes, persists consumed quota, and performs guest containment. On restart, use the same
ledger and current policy; do not rerun prior active steps to reconstruct history. A new
orchestration run may reference prior evidence, but it must not erase previous usage or
silently relabel prior failures as a new passing result.
