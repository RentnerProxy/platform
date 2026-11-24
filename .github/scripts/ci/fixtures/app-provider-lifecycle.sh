#!/usr/bin/env bash
set -euo pipefail

# Run the signed app lifecycle natively. Its fixture app advertises a provider, so every
# install, update, restart, rollback and recovery must register it for its own generation.
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) native=amd64 ;;
    Linux/aarch64) native=arm64 ;;
    *) printf 'Expected native Linux AMD64 or ARM64\n' >&2; exit 1 ;;
esac
test "$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')" = "linux/$native"

artifacts=$(cargo test --locked --manifest-path core/Cargo.toml --all-features --no-run --message-format=json-render-diagnostics)
app_tests=$(jq -er 'select(.reason == "compiler-artifact" and .target.kind == ["lib"] and .profile.test) | .executable // empty' <<< "$artifacts")
controller=$(jq -er 'select(.reason == "compiler-artifact" and .target.name == "rentnerproxy-controller" and .target.kind == ["bin"] and (.profile.test | not)) | .executable // empty' <<< "$artifacts")
test -x "$app_tests"
test -x "$controller"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
objcopy --strip-debug "$app_tests" "$work/app-tests"
objcopy --strip-debug "$controller" "$work/controller"
rustc --edition=2024 -C opt-level=s -C strip=symbols \
    core/tests/fixtures/app-manager/app.rs -o "$work/fixture-app"

docker run --rm --network none --read-only --user 0:0 \
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add KILL \
    --cap-add SETGID --cap-add SETUID --security-opt no-new-privileges \
    --tmpfs '/run:rw,exec,mode=0755,size=512m' \
    --tmpfs '/var/lib/rentnerproxy:rw,exec,mode=0755,size=128m' \
    --tmpfs '/tmp:rw,mode=01777,size=128m' \
    --mount "type=bind,source=$work/app-tests,target=/app-tests,readonly" \
    --mount "type=bind,source=$work/controller,target=/controller,readonly" \
    --mount "type=bind,source=$work/fixture-app,target=/fixture-app,readonly" \
    --env RENTNERPROXY_TEST_CONTROLLER=/controller \
    --env RENTNERPROXY_TEST_APP=/fixture-app \
    mirror.gcr.io/library/rust:1.100.0-trixie \
    /app-tests --ignored --exact app_manager::tests::privileged_signed_lifecycle
