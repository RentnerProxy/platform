#!/usr/bin/env bash
set -euo pipefail

# Run the app IPC and UI boundary fixtures that need real UID changes on the native architecture.
# The coverage job runs the same fixtures on AMD64 only; this proves them on ARM64 as well.
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

runner=(
    docker run --rm --network none --read-only --user 0:0
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add KILL
    --cap-add SETGID --cap-add SETUID --security-opt no-new-privileges
    --tmpfs '/run:rw,exec,mode=0755,size=512m'
    --mount "type=bind,source=$work/app-tests,target=/app-tests,readonly"
    --mount "type=bind,source=$work/controller,target=/controller,readonly"
    --env RENTNERPROXY_TEST_CONTROLLER=/controller
)
"${runner[@]}" \
    mirror.gcr.io/library/ubuntu:24.04 \
    /app-tests --test-threads=1 --ignored app_ipc::tests::privileged_
# The application verifier cross-checks ELF linkage with the image's readelf.
"${runner[@]}" \
    --tmpfs /root:rw,mode=0700,size=64m \
    --tmpfs /tmp:rw,mode=01777,size=128m \
    mirror.gcr.io/library/rust:1.100.0-trixie \
    bash -eu -c '
        /app-tests --test-threads=1 app_manager::ui::tests:: \
            app_ipc::tests::root_ui_ app_ipc::tests::root_provider_
        /app-tests --test-threads=1 --ignored --exact \
            app_manager::ui::tests::privileged_web_socket_serves_generation_scoped_ui
    '
