#!/bin/sh
# Explicit reviewed setup only; proofs never invoke a compiler.
set -eu
[ "$#" -eq 1 ] && [ "$1" = "--confirm-build" ] || { echo 'requires --confirm-build' >&2; exit 2; }
[ "$(/usr/bin/uname -s)" = Darwin ] && [ "$(/usr/bin/uname -m)" = arm64 ] || { echo 'macOS arm64 fixture only' >&2; exit 2; }
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
umask 077
uid=$(/usr/bin/id -u)
validate_ancestors() {
    path=$1
    while :; do
        [ -d "$path" ] && [ ! -L "$path" ] || exit 2
        owner=$(/usr/bin/stat -f '%u' "$path")
        mode=$(/usr/bin/stat -f '%Lp' "$path")
        [ "$owner" -eq "$uid" ] || [ "$owner" -eq 0 ] || exit 2
        case "$mode" in *[2367][0-7]|*[0-7][2367]) exit 2 ;; esac
        [ "$path" != / ] || break
        path=$(/usr/bin/dirname "$path")
    done
}
validate_ancestors "$repo"
for path in "$repo/target" "$repo/target/r0-tools"; do
    if [ ! -e "$path" ]; then /bin/mkdir "$path"; fi
    validate_ancestors "$path"
done
out="$repo/target/r0-tools/storage-faults"
# mkdir reserves a fresh output name atomically and cannot adopt unrelated output.
/bin/mkdir "$out"
temporary=$(/usr/bin/mktemp -d "$repo/target/r0-tools/storage-fault-build.XXXXXXXX")
trap '/bin/rm -f "$temporary/sync_eio.dylib" "$temporary/build-manifest.txt"; /bin/rmdir "$temporary"' EXIT HUP INT TERM
/usr/bin/clang -std=c11 -Wall -Wextra -Werror -O2 -dynamiclib -arch arm64 \
    "$repo/fixtures/storage-faults/sync_eio.c" -o "$temporary/sync_eio.dylib"
{
    /usr/bin/clang --version
    /usr/bin/shasum -a 256 "$repo/fixtures/storage-faults/sync_eio.c" "$repo/scripts/proofs/build-storage-fault.sh" "$temporary/sync_eio.dylib"
} > "$temporary/build-manifest.txt"
# link is no-clobber; remove each staging name before the fixture can be used.
/bin/ln "$temporary/sync_eio.dylib" "$out/sync_eio.dylib"
/bin/rm "$temporary/sync_eio.dylib"
/bin/ln "$temporary/build-manifest.txt" "$out/build-manifest.txt"
/bin/rm "$temporary/build-manifest.txt"
/bin/cat "$out/build-manifest.txt"
