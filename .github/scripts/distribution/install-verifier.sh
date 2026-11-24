#!/bin/bash
set -Eeuo pipefail
: "${RUNNER_TEMP:?}" "${GITHUB_PATH:?}"
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
manifest="$directory/../../../core/distribution-tooling/Cargo.toml"
target="$RUNNER_TEMP/distribution-verifier-target"
bin="$RUNNER_TEMP/distribution-verifier-bin"
platform="$(uname -m)-unknown-linux-musl"
rustup toolchain install 1.100.0 --profile minimal
rustup target add --toolchain 1.100.0 "$platform"
cargo +1.100.0 build --release --locked --target "$platform" --manifest-path "$manifest" --target-dir "$target"
install -D -m 0755 -- "$target/$platform/release/rentnerproxy-distribution-verify" "$bin/rentnerproxy-distribution-verify"
printf '%s\n' "$bin" >> "$GITHUB_PATH"
