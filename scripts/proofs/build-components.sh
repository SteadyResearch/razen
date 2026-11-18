#!/bin/bash
set -euo pipefail
umask 077
[ "$#" -eq 0 ] || { echo 'no arguments accepted; invoke explicitly to build reviewed fixtures' >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT"
WIT=specs/001-r0-feasibility/contracts/plugin-sdk.wit
PIN=c1fa7edeab97ff43ccca45f898a5155f8c43cfb06937be8c247bcde1b0e760c9
sha() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
[ "$(sha "$WIT")" = "$PIN" ] || { echo 'public WIT pin changed' >&2; exit 1; }
[ "$(rustc +1.100.0 --version | cut -d ' ' -f 2)" = 1.100.0 ]
UID_NOW=$(/usr/bin/id -u)
validate_ancestors() {
    local path=$1 owner mode
    while :; do
        [ -d "$path" ] && [ ! -L "$path" ] || exit 2
        owner=$(/usr/bin/stat -f '%u' "$path")
        mode=$(/usr/bin/stat -f '%Lp' "$path")
        [ "$owner" -eq "$UID_NOW" ] || [ "$owner" -eq 0 ] || exit 2
        case "$mode" in *[2367][0-7]|*[0-7][2367]) exit 2 ;; esac
        [ "$path" != / ] || break
        path=$(/usr/bin/dirname "$path")
    done
}
validate_output_file() {
    if [ -e "$1" ] || [ -L "$1" ]; then
        [ -f "$1" ] && [ ! -L "$1" ] \
            && [ "$(/usr/bin/stat -f '%u:%l:%Lp' "$1")" = "$UID_NOW:1:600" ] || exit 2
    fi
}
OUT=target/proof-components
validate_ancestors "$ROOT"
for DIRECTORY in target "$OUT" target/component-build; do
    [ -e "$DIRECTORY" ] || /bin/mkdir "$DIRECTORY"
    validate_ancestors "$ROOT/$DIRECTORY"
done
cargo +1.100.0 build --locked --offline -p razen-engine --bin razen-component-runner
MANIFEST="$OUT/build-manifest.json"
validate_output_file "$MANIFEST"
TMP=$(/usr/bin/mktemp "$OUT/.build-manifest.XXXXXXXX")
STAGED=''
trap 'rm -f "$TMP"; if [ -n "$STAGED" ]; then rm -f "$STAGED"; fi' EXIT
printf '{"schema_version":"0.1.0","rust":"1.100.0","target":"wasm32-wasip2","wit_bindgen":"0.63.0","wasmtime":"50.0.2","wit_sha256":"%s","lock_sha256":"%s","guest_manifest_sha256":"%s","guest_source_sha256":"%s","bindings_sha256":"%s","helper_sha256":"%s","runner_sha256":"%s","variants":[' "$PIN" "$(sha fixtures/components/Cargo.lock)" "$(sha fixtures/components/Cargo.toml)" "$(sha fixtures/components/src/lib.rs)" "$(sha fixtures/components/src/bindings.rs)" "$(sha scripts/proofs/build-components.sh)" "$(sha target/debug/razen-component-runner)" > "$TMP"
SEP=''
for VARIANT in fixture-valid fixture-loop fixture-grow fixture-output fixture-host-call fixture-denied-access; do
    cargo +1.100.0 build --manifest-path fixtures/components/Cargo.toml --target wasm32-wasip2 --release --locked --offline --no-default-features --features "$VARIANT" --target-dir "$ROOT/target/component-build"
    SOURCE="target/component-build/wasm32-wasip2/release/razen_component_fixtures.wasm"
    DEST="$OUT/$VARIANT.wasm"
    validate_output_file "$DEST"
    STAGED=$(/usr/bin/mktemp "$OUT/.$VARIANT.XXXXXXXX")
    cp "$SOURCE" "$STAGED"
    chmod 600 "$STAGED"
    mv -f "$STAGED" "$DEST"
    STAGED=''
    printf '%s{"variant":"%s","file":"%s.wasm","sha256":"%s","length_bytes":%s}' "$SEP" "$VARIANT" "$VARIANT" "$(sha "$DEST")" "$(wc -c < "$DEST" | tr -d ' ')" >> "$TMP"
    SEP=,
done
printf ']}' >> "$TMP"
chmod 600 "$TMP"
mv "$TMP" "$MANIFEST"
printf 'Built six distinct public-WIT components: %s\n' "$MANIFEST"
