#!/bin/bash
# Runs ONLY as root inside the new owned Debian VM, never on the macOS host.
set -euo pipefail
umask 077
[ "$#" = 1 ]
[ "$1" = --confirm-provision ]
[ "$(id -u)" = 0 ]
[ "$(uname -m)" = aarch64 ]
[ "$(cat /etc/debian_version)" = 13.7 ]
base=/var/lib/razen
install -d -m 0700 "$base" "$base/invocations" "$base/build" "$base/credentials" "$base/private-other"
install -d -m 0755 "$base/inputs" /usr/local/libexec /usr/local/share/razen /usr/local/share/razen/runtime /opt/razen
chmod 0755 "$base"
# The dated snapshot and Debian's signed Release/Packages indexes pin dependency bytes.
cat > /etc/apt/sources.list.d/razen.sources <<'SOURCES'
Types: deb
URIs: https://snapshot.debian.org/archive/debian/20261112T000000Z/
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no

Types: deb
URIs: https://snapshot.debian.org/archive/debian-security/20261112T000000Z/
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
SOURCES
for file in /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
  [ -e "$file" ] || continue
  [ "$file" = /etc/apt/sources.list.d/razen.sources ] || mv "$file" "$file.razen-disabled"
done
[ ! -f /etc/apt/sources.list ] || mv /etc/apt/sources.list /etc/apt/sources.list.razen-disabled
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Check-Valid-Until=false update
packages=(build-essential meson ninja-build pkg-config libcap-dev curl xz-utils ca-certificates python3 kmod sudo)
exact=()
for package in "${packages[@]}"; do
  version=$(apt-cache policy "$package" | awk '/Candidate:/ {print $2; exit}')
  [ -n "$version" ] && [ "$version" != '(none)' ]
  exact+=("$package=$version")
done
apt-get install -y --no-install-recommends "${exact[@]}"
cd "$base/build"
fetch() { local url=$1 file=$2 digest=$3; if [ ! -f "$file" ]; then curl --fail --location --proto '=https' --tlsv1.2 "$url" -o "$file.partial"; mv "$file.partial" "$file"; fi; printf '%s  %s\n' "$digest" "$file" | sha256sum --check --status; }
fetch https://static.rust-lang.org/dist/rust-1.100.0-aarch64-unknown-linux-gnu.tar.xz rust.tar.xz a21f6a21818df07c1e2e7addb570af5444b3fa9dd61e3a207f4fb1c5a5e665c9
if [ ! -x /opt/razen/rust-1.100.0/bin/rustc ]; then
  tar -xf rust.tar.xz
  ./rust-1.100.0-aarch64-unknown-linux-gnu/install.sh --prefix=/opt/razen/rust-1.100.0 --without=rust-docs
fi
[ "$(/opt/razen/rust-1.100.0/bin/rustc --version | awk '{print $2}')" = 1.100.0 ]
fetch https://github.com/containers/bubblewrap/releases/download/v0.13.1/bubblewrap-0.13.1.tar.xz bubblewrap.tar.xz 0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d
if [ ! -x /usr/local/bin/bwrap ] || [ "$(/usr/local/bin/bwrap --version)" != 'bubblewrap 0.13.1' ]; then
  tar -xf bubblewrap.tar.xz
  if [ -f bubblewrap-build/meson-private/coredata.dat ]; then mode=--reconfigure; else mode=; fi
  meson setup $mode bubblewrap-build bubblewrap-0.13.1 --prefix=/usr/local -Dtests=false -Dman=disabled -Dbash_completion=disabled -Dzsh_completion=disabled -Dselinux=disabled
  ninja -C bubblewrap-build
  ninja -C bubblewrap-build install
fi
# Only the reviewed Cargo.toml, lock and src tree were copied. No .cargo/config or hooks.
install -d -m 0700 "$base/build/source" "$base/build/cargo-home"
upload=$(python3 -c 'import json; print(json.load(open("/tmp/razen-provenance.json"))["upload_sha256"])')
printf '%s  %s\n' "$upload" /tmp/razen-source.tar | sha256sum --check --status
provision=$(python3 -c 'import json; print(json.load(open("/tmp/razen-provenance.json"))["provisioning_sha256"])')
printf '%s  %s\n' "$provision" /tmp/razen-provision.sh | sha256sum --check --status
tar -xf /tmp/razen-source.tar -C "$base/build/source" --no-same-owner
cd "$base/build/source/fixtures/linux-runner"
export PATH=/opt/razen/rust-1.100.0/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CARGO_HOME="$base/build/cargo-home"
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
cargo fetch --locked
cargo build --offline --locked --release
install -m 0755 target/release/razen-tool-supervisor /usr/local/libexec/razen-tool-supervisor
install -m 0555 target/release/razen-sandbox-adversary /usr/local/share/razen/runtime/razen-sandbox-adversary
# Construct the minimal read-only runtime, not /usr or a host/repository mount.
while read -r library; do
  [ -f "$library" ] || exit 1
  install -d -m 0755 "/usr/local/share/razen/runtime$(dirname "$library")"
  install -m 0555 "$library" "/usr/local/share/razen/runtime$library"
done < <(ldd target/release/razen-sandbox-adversary | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' | sort -u)
if ! getent group razen-workload >/dev/null; then groupadd --gid 61000 razen-workload; fi
if ! getent passwd razen-workload >/dev/null; then useradd --uid 61000 --gid 61000 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin razen-workload; fi
[ "$(id -u razen-workload)" = 61000 ] && [ "$(id -g razen-workload)" = 61000 ]
[ "$(id -G razen-workload)" = 61000 ]
usermod --lock razen-workload
set +e
/usr/bin/sudo -n -u razen-workload -- /usr/bin/true
healthy_exit=$?
/usr/bin/sudo -n -u razen-workload -- /usr/bin/sudo -n -- /usr/bin/true
denied_exit=$?
# Query an actual root command: a successful listing alone does not grant that command.
/usr/bin/sudo -n -l -U razen-workload -- /usr/bin/true
policy_exit=$?
set -e
printf 'Observed sudo control exits: healthy=%s denied=%s policy=%s\n' "$healthy_exit" "$denied_exit" "$policy_exit"
[ "$healthy_exit" = 0 ]
[ "$denied_exit" = 1 ]
[ "$policy_exit" = 1 ]
sudo_policy=$(/usr/local/libexec/razen-tool-supervisor --sudo-policy-hash)
printf '{"healthy_exit":%s,"denied_exit":%s,"policy_exit":%s,"sudo_policy_sha256":"%s"}\n' "$healthy_exit" "$denied_exit" "$policy_exit" "$sudo_policy" > /usr/local/share/razen/sudo-checks.json
chmod 0444 /usr/local/share/razen/sudo-checks.json
# Root alone owns management/cgroups. Workload gets no sudo membership or login.
chmod 0755 /usr/local/bin/bwrap
for controller in cpu memory pids; do grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers; done
modprobe vsock
modprobe vsock_loopback
printf '+cpu +memory +pids\n' > /sys/fs/cgroup/cgroup.subtree_control
mkdir -p /sys/fs/cgroup/razen-proof
printf '+cpu +memory +pids\n' > /sys/fs/cgroup/razen-proof/cgroup.subtree_control
: > "$base/invocation.lock"
chmod 0600 "$base/invocation.lock"
for canary in "$base/manager-canary" "$base/credentials/synthetic" "$base/private-other/snapshot"; do [ -f "$canary" ] || head -c 32 /dev/urandom > "$canary"; chmod 0600 "$canary"; done
/usr/local/libexec/razen-tool-supervisor --compile-seccomp > /usr/local/share/razen/seccomp.bpf
chmod 0444 /usr/local/share/razen/seccomp.bpf
install -m 0600 /tmp/razen-provenance.json /usr/local/share/razen/provenance.json
# Actual installed versions + immutable archive/provision/source hashes are retained.
# The maintained APT API is setup-only; its installed version is captured below too.
apt_python_version=$(apt-cache policy python3-apt | awk '/Candidate:/ {print $2; exit}')
[ -n "$apt_python_version" ] && [ "$apt_python_version" != '(none)' ]
apt-get install -y --no-install-recommends "python3-apt=$apt_python_version"
dpkg-query -W -f='${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n' | awk -F '\t' '$1 == "installed" {printf "%s\t%s\t%s\n", $2, $3, $4}' | LC_ALL=C sort > /usr/local/share/razen/packages.tsv
chmod 0444 /usr/local/share/razen/packages.tsv
sha256sum /var/lib/dpkg/status | awk '{print $1}' > /usr/local/share/razen/dpkg-status.sha256
chmod 0444 /usr/local/share/razen/dpkg-status.sha256
install -d -m 0755 /usr/local/share/razen/licenses
cp "$base/build/bubblewrap-0.13.1/COPYING" /usr/local/share/razen/licenses/bubblewrap-COPYING
# Preserve original installed-package license and signed-repository metadata during explicit setup.
captures="$base/dependency-captures/guest-packages"
[ ! -e "$captures" ]
install -d -m 0700 "$captures"
cp /usr/local/share/razen/packages.tsv "$captures/packages.tsv"
while IFS=$'\t' read -r package version architecture; do
  case "$package" in ''|*[!a-z0-9+.-]*) printf 'Invalid installed package name\n' >&2; exit 1 ;; esac
  case "$architecture" in arm64|all) ;; *) printf 'Unsupported installed package architecture\n' >&2; exit 1 ;; esac
  copyright="/usr/share/doc/$package/copyright"
  [ -f "$copyright" ] || { printf 'Missing original copyright for installed package %s\n' "$package" >&2; exit 1; }
  cp -L -- "$copyright" "$captures/$package.$architecture.copyright"
  apt-cache policy "$package" > "$captures/$package.$architecture.policy"
  apt-cache show --all-versions "$package=$version" > "$captures/$package.$architecture.metadata"
done < /usr/local/share/razen/packages.tsv
# APT parses its own control data. Human policy output and freeform copyright
# remain original private captures, never a homemade Deb822/DEP5 interpretation.
/usr/bin/python3 - "$captures" <<'PY'
import apt
import apt_pkg
import hashlib
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote

root = Path(sys.argv[1])
cache = apt.Cache()
source_cache = apt_pkg.Cache(None)
source_records = apt_pkg.PackageRecords(source_cache)
sources = apt_pkg.SourceList()
sources.read_main_list()
archive_uris = (
    "https://snapshot.debian.org/archive/debian/20261112T000000Z/",
    "https://snapshot.debian.org/archive/debian-security/20261112T000000Z/",
)

def artifact(record, identity):
    filename, digest = record.get("Filename"), record.get("SHA256")
    if not filename or not digest:
        return None
    if (not filename.startswith("pool/") or
            any(part in ("", ".", "..") for part in filename.split("/")) or
            not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise RuntimeError(f"Invalid indexed APT source artifact for {identity}")
    return filename, digest

for line in (root / "packages.tsv").read_text().splitlines():
    name, version, architecture = line.split("\t")
    prefix = root / f"{name}.{architecture}"
    identity = f"{name}={version} ({architecture})"
    package = cache[name]
    installed, candidate = package.installed, package.candidate
    if installed is None or candidate is None or installed.version != version or installed.architecture != architecture:
        raise RuntimeError(f"Installed APT identity differs from dpkg capture for {identity}")
    with open(f"{prefix}.metadata") as source:
        records = [dict(record) for record in apt_pkg.TagFile(source)]
    matching = [record for record in records
                if (record.get("Package"), record.get("Version"), record.get("Architecture"))
                == (name, version, architecture)]
    captured_artifacts = {value for record in matching
                          if (value := artifact(record, identity)) is not None}
    indexed_artifacts = set()
    indexed_uris = {}
    indexed_sources = []
    indexed_source_count = 0
    for selected in source_cache[name].version_list:
        if selected.ver_str != version or selected.arch != architecture:
            continue
        for location in selected.file_list:
            index = sources.find_index(location[0])
            if index is None:
                continue  # dpkg status is retained in raw output, never source evidence.
            if not index.is_trusted:
                raise RuntimeError(f"Untrusted indexed APT source for {identity}")
            if not source_records.lookup(location):
                raise RuntimeError(f"Cannot read indexed APT source for {identity}")
            record = apt_pkg.TagSection(source_records.record)
            if (record.get("Package"), record.get("Version"), record.get("Architecture")) != (name, version, architecture):
                raise RuntimeError(f"Indexed APT control identity mismatch for {identity}")
            value = artifact(record, identity)
            if value is None:
                raise RuntimeError(f"Incomplete indexed APT source for {identity}: Filename and SHA256 required")
            indexed_artifacts.add(value)
            uri = index.archive_uri(value[0])
            indexed_uris.setdefault(value, []).append(uri)
            indexed_source_count += 1
            if len(indexed_sources) < 8:
                indexed_sources.append({
                    "filename": value[0][:1024], "sha256": value[1],
                    "index": index.describe[:1024],
                    "uri": uri[:2048],
                    "trusted": index.is_trusted,
                })
    if not indexed_artifacts or not captured_artifacts:
        raise RuntimeError(f"No authentic indexed APT source for {identity}: Filename and SHA256 required")
    installed_uris = installed.uris
    if (len({digest for _, digest in indexed_artifacts}) != 1 or
            not captured_artifacts <= indexed_artifacts):
        # Only bounded public repository identities enter diagnostics; raw captures stay private.
        details = {
            "captured_artifacts": [[filename[:1024], digest]
                                   for filename, digest in sorted(captured_artifacts)[:8]],
            "captured_artifacts_omitted": max(0, len(captured_artifacts) - 8),
            "indexed_artifacts": [[filename[:1024], digest]
                                  for filename, digest in sorted(indexed_artifacts)[:8]],
            "indexed_artifacts_omitted": max(0, len(indexed_artifacts) - 8),
            "indexed_sources": indexed_sources,
            "indexed_sources_omitted": max(0, indexed_source_count - 8),
            "installed_uris": [uri[:2048] for uri in installed_uris[:8]],
            "installed_uris_omitted": max(0, len(installed_uris) - 8),
            "diagnostic_entry_limit": 8,
            "diagnostic_filename_index_limit": 1024,
            "diagnostic_uri_limit": 2048,
        }
        raise RuntimeError(
            f"Conflicting or incomplete selected APT source capture for {identity}: "
            + json.dumps(details, sort_keys=True))
    # Identical bytes may have repository-specific filenames. Keep a filename
    # present in the original capture paired with that exact index's real URI.
    filename, digest = min(captured_artifacts)
    selected_uri = None
    for uri in indexed_uris[(filename, digest)]:
        if (len(uri.encode("utf-8")) <= 4095 and
                not any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in uri) and
                any(uri.startswith(base) and unquote(uri[len(base):]) == filename for base in archive_uris)):
            selected_uri = uri
            break
    if selected_uri is None:
        raise RuntimeError(f"No authentic installed-version APT repository URI for {identity}")
    Path(f"{prefix}.uri").write_text(selected_uri + "\n")
    facts = {
        "parser": "python3-apt",
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "parser_version": cache["python3-apt"].installed.version,
        "name": name, "version": version, "architecture": architecture,
        "installed": installed.version, "candidate": candidate.version,
        "candidate_origins": [
            {"origin": origin.origin, "archive": origin.archive,
             "site": origin.site, "trusted": origin.trusted}
            for origin in candidate.origins
        ],
        "filename": filename, "sha256": digest,
        "copyright_raw_sha256": hashlib.sha256(Path(f"{prefix}.copyright").read_bytes()).hexdigest(),
        "policy_raw_sha256": hashlib.sha256(Path(f"{prefix}.policy").read_bytes()).hexdigest(),
        "metadata_raw_sha256": hashlib.sha256(Path(f"{prefix}.metadata").read_bytes()).hexdigest(),
        "license_expression": "NOASSERTION",
        "license_reference": "original-installed-package-copyright",
    }
    Path(f"{prefix}.facts.json").write_text(json.dumps(facts, sort_keys=True) + "\n")
PY
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$captures/checked-at.txt"
chmod 0600 "$captures/"*
/usr/local/libexec/razen-tool-supervisor --inspect
