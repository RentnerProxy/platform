#!/usr/bin/env bash
set -euo pipefail

# Provision app databases and run declared data migrations natively against a disposable
# PostgreSQL cluster that uses the production client authentication.
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) native=amd64 ;;
    Linux/aarch64) native=arm64 ;;
    *) printf 'Expected native Linux AMD64 or ARM64\n' >&2; exit 1 ;;
esac
test "$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')" = "linux/$native"

artifacts=$(cargo test --locked --manifest-path core/Cargo.toml --all-features --no-run --message-format=json-render-diagnostics)
ipc_tests=$(jq -er 'select(.reason == "compiler-artifact" and .target.kind == ["lib"] and .profile.test) | .executable // empty' <<< "$artifacts")
controller=$(jq -er 'select(.reason == "compiler-artifact" and .target.name == "rentnerproxy-controller" and .target.kind == ["bin"] and (.profile.test | not)) | .executable // empty' <<< "$artifacts")
test -x "$ipc_tests"
test -x "$controller"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
objcopy --strip-debug "$ipc_tests" "$work/ipc-tests"
objcopy --strip-debug "$controller" "$work/controller"

docker run --rm --network none --read-only --user 0:0 \
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add KILL \
    --cap-add SETGID --cap-add SETUID --security-opt no-new-privileges \
    --tmpfs '/run:rw,exec,mode=0755,size=128m' \
    --tmpfs '/var/lib/rentnerproxy:rw,mode=0755,size=64m' \
    --tmpfs '/tmp:rw,mode=01777,size=128m' \
    --mount "type=bind,source=$work/ipc-tests,target=/ipc-tests,readonly" \
    --mount "type=bind,source=$work/controller,target=/controller,readonly" \
    --mount "type=bind,source=$PWD/docker/production/tests/app-provision.sh,target=/app-provision.sh,readonly" \
    --mount "type=bind,source=$PWD/docker/production/apps/pg_hba.conf,target=/fixture/pg_hba.conf,readonly" \
    --mount "type=bind,source=$PWD/docker/production/apps/pg_ident.conf,target=/fixture/pg_ident.conf,readonly" \
    --env RENTNERPROXY_TEST_CONTROLLER=/controller \
    --entrypoint /bin/bash \
    mirror.gcr.io/library/postgres:18.7-trixie \
    /app-provision.sh
