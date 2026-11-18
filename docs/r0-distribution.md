# R0 Distribution and Source Integrity

## Scope and publication gate

R0 is a constrained, local feasibility harness, not a published product or a redistributable
VM image. Passing runtime proofs does not approve publication, choose the product license,
or establish third-party license compliance. Product identity/license and signed package
publication remain separate governance gates.

Local host binaries and approved fixture components are development artifacts. Do not grant
additional authority because a binary is signed, a checksum matches, or code executes as WASM.
No OS trust installation or disabled TLS verification is required for R0.

## Captured source evidence

The three independently locked Cargo workspaces select 418 distinct registry name/version
pairs: 407 occur in the host graph. The union, rather than the sum of workspace counts, is the
source inventory. Original authoritative registry responses and downloaded source archives
are retained under `target/r0-evidence/preparation/`; archive bytes are checked against the
published digest. A published digest alone is not downloaded-byte verification.

`target/r0-evidence/distribution/rust-notices-current.json` records
those 418 archives and 689 filename-matched notice-document candidates with original member
hashes. Six Rust source files whose names resemble license documents are explicitly excluded
in `rust-notice-exclusions-current.json`. Forty-six archives have no matching standalone notice
filename. Their original source and license expressions require inspection before redistribution;
filename matching is not a legal completeness or copyright-attribution determination.

Preserve exact upstream license expressions, including legacy slash-separated alternatives.
SPDX parsing recognizes that historical syntax without rewriting the claim or choosing a
license branch. `NOASSERTION` and freeform installed-package copyright are not invented SPDX
licenses or legal clearance.

## Attribution and source obligations

- Preserve original license texts, copyright statements and applicable `NOTICE` files for
  MIT, Apache, BSD, ISC, Zlib, Unlicense and other selected terms. Record any chosen `OR`
  branch before publication; cumulative `AND` terms still apply together.
- Wasmtime/Cranelift and related selections include `Apache-2.0 WITH LLVM-exception`.
  Preserve the actual exception and notices; do not shorten the claim to Apache-2.0.
- Unicode data/code and web PKI root selections have their own Unicode-3.0 and
  CDLA-Permissive-2.0 notices. Root certificates are not product-owned text.
- Two selected `r-efi` versions offer LGPL-2.1-or-later as an alternative to MIT/Apache.
  Do not describe an unrecorded alternative choice as an approved distribution decision.
- The pinned Lima bundle includes its original Apache license at
  `share/doc/lima/LICENSE`. Its bundle also contains non-Cargo tooling; the Cargo inventory
  does not establish completeness of that tool's own transitive attributions.
- bubblewrap 0.13.1's exact source archive is retained under
  `target/r0-evidence/distribution/original-sources/`; its checksum matches the reviewed pin.
  The original `COPYING` contains LGPL version 2.1 text. Preserve upstream file-level terms,
  corresponding source, build instructions, modification notices and applicable relinking
  rights rather than labeling the compiled helper permissive.
- A prepared Debian guest contains packages, build tools, a Rust toolchain and kernel code
  with mixed licenses. Review each original installed-package copyright and signed-repository
  source fact exported by explicit preparation. Preserve required corresponding source and
  notices before distributing an image or compiled dependencies. Never assign a single
  permissive license to the complete image.

`target/r0-evidence/distribution/guest-installed-source-notices-reviewed-launcher.json`
binds all 388 current installed packages to their original copyright, policy, metadata,
signed-source facts, exact package manifest and reviewed launcher preparation. Of these,
326 have machine-readable `License:` headers and 62 require the original text instead.
The headers are a lookup index, not SPDX normalization, full review or redistribution clearance.

## Signature and authenticity limits

All five locally built host programs (proof CLI, engine, component runner, receiver and
command fixture) passed `codesign --verify --strict` on 2026-11-18. Exact byte hashes,
displayed signatures and exit codes are retained in
`target/r0-evidence/distribution/local-executable-signatures-canonical-binding.txt`.
All five display ad-hoc signatures without a publisher team identity. Earlier four-program
and pinned Lima-manager observations remain retained separately. Each observation binds
only its recorded artifact, not future rebuilds. Ad-hoc integrity is not publisher signature
authenticity, notarization, harmlessness or publication approval.

The reviewed Lima release publishes a detached checksum signature, but its authenticity has
not been verified here. The Debian image pin is a SHA-512 byte-integrity selection; no
verified detached image-manifest signature is claimed. Debian package facts must retain the
actual trusted APT origin, candidate version and original metadata, not a reconstructed
claim that a package was signed.

Before publication, resolve the open product license, complete third-party attribution and
source obligations, verify required publisher signatures/provenance, and review a fresh
exact artifact manifest. R0 maintainer acceptance cannot silently waive those gates.

## Advisory observations

The retained 2026-11-17 OSV batch response covered 416 then-selected public Cargo name/version
pairs and reported Chrono's newly issued
[RUSTSEC-2026-0543](https://rustsec.org/advisories/RUSTSEC-2026-0543.html). Its classification
is informational unmaintained, not a reported exploitable vulnerability; no patched version
exists. The current maintained replacement is Jiff 1.0.1, built for both host and native Linux
consumers. No advisory waiver or approval of the older selection is invented.

The actual 2026-11-18 OSV query covers all 418 current exact Rust selections and reports no
matched advisory entries. Original `osv-current-query.json` and `osv-current-response.json`
are retained under `target/r0-evidence/distribution/`; `osv-current-disposition.json` binds
that result to their hashes and the current workspace captures. Chrono is absent.

This observation does not cover embedded C/C++ source, Lima's Go dependencies, Debian packages,
kernel code, future versions or future advisory updates. An empty advisory intersection is
not a claim that the harness is harmless or approved for publication.
