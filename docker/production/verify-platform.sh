#!/bin/sh
set -eu

target_os=${1:?Usage: verify-platform.sh OS ARCH BINARY...}
target_arch=${2:?Usage: verify-platform.sh OS ARCH BINARY...}
shift 2
test "$#" -gt 0
case "$target_os/$target_arch" in
    linux/amd64) machine=3e00; kernel_machine=x86_64 ;;
    linux/arm64) machine=b700; kernel_machine=aarch64 ;;
    *) echo 'Unsupported appliance platform' >&2; exit 1 ;;
esac
test "$(uname -s)/$(uname -m)" = "Linux/$kernel_machine"

for binary do
    # Require little-endian ELF64 and the actual target CPU, including copied binaries.
    test "$(od -An -tx1 -N6 "$binary" | tr -d ' \n')" = 7f454c460201
    test "$(od -An -tx1 -j18 -N2 "$binary" | tr -d ' \n')" = "$machine"
    headers=$(readelf --wide --program-headers --dynamic "$binary")
    if printf '%s\n' "$headers" | grep -q '^[[:space:]]*INTERP[[:space:]]'; then
        linkage=$(ldd "$binary") || { echo "Invalid runtime linkage: $binary" >&2; exit 1; }
        case "$linkage" in *'not found'*) echo "Missing runtime library: $binary" >&2; exit 1 ;; esac
    elif printf '%s\n' "$headers" | grep -q '(NEEDED)'; then
        echo "Missing runtime interpreter: $binary" >&2
        exit 1
    fi
done
