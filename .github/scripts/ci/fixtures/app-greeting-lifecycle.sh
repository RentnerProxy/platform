#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --container ]]; then
    postgres=/usr/lib/postgresql/18/bin
    database=/tmp/greeting-postgres
    install -d -m 0700 -o postgres -g postgres "$database" /var/run/postgresql
    install -d -m 0711 /run/rentnerproxy
    install -d -m 0755 -o postgres -g postgres /run/rentnerproxy/app-db
    gosu postgres "$postgres/initdb" --pgdata="$database" --auth-local=peer \
        --auth-host=scram-sha-256 --encoding=UTF8 --no-locale >/dev/null

    stop_postgres() {
        local status=$?
        if gosu postgres "$postgres/pg_ctl" --pgdata="$database" status >/dev/null 2>&1; then
            if ((status != 0)); then
                cat "$database/server.log" >&2
            fi
            gosu postgres "$postgres/pg_ctl" --pgdata="$database" --mode=fast --wait --timeout=15 stop >/dev/null || status=1
        fi
        exit "$status"
    }
    trap stop_postgres EXIT
    gosu postgres "$postgres/pg_ctl" --pgdata="$database" --log="$database/server.log" --wait --timeout=15 \
        --options='-c listen_addresses= -c unix_socket_directories=/var/run/postgresql,/run/rentnerproxy/app-db -c hba_file=/fixture/pg_hba.conf -c ident_file=/fixture/pg_ident.conf' start >/dev/null
    /app-tests --ignored --exact app_manager::tests::lifecycle::published_greeting::privileged_published_greeting_lifecycle --nocapture
    test -s "$RP_GREETING_LIFECYCLE_REPORT"
    exit
fi

output=${1:?Expected an evidence output directory}
fixture_script=$(realpath "${BASH_SOURCE[0]}")
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) native=amd64 ;;
    Linux/aarch64) native=arm64 ;;
    *) printf 'Expected native Linux AMD64 or ARM64\n' >&2; exit 1 ;;
esac
test "$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')" = "linux/$native"

mkdir -p "$output"
output=$(realpath "$output")
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
rm -f -- "$output/greeting-lifecycle.json"

download() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 90 --retry 2 --retry-max-time 100 \
        --max-filesize "$1" --output "$2" "$3"
}

snapshot() {
    local version=$1 commit=$2 revision=$3 target=$4
    local source="https://raw.githubusercontent.com/RentnerProxy/app-catalog/$commit"
    local destination="$work/v$version" path
    mkdir -p "$destination/metadata" "$destination/targets"
    for path in \
        metadata/1.root.json \
        metadata/timestamp.json \
        "metadata/$revision.snapshot.json" \
        "metadata/$revision.targets.json" \
        "targets/$target.catalog.json"; do
        download 1048576 "$destination/$path" "$source/$path"
    done

    local archive="rentnerproxy.greeting-$version-linux-$native.tar.zst"
    download 55000000 "$work/$archive" \
        "https://github.com/RentnerProxy/app-catalog/releases/download/rentnerproxy.greeting-v$version/$archive"
}

# Use immutable release bytes and exact catalog revisions even after a new app version ships.
snapshot 1.0.0 44557b84bce0a63cb71aadc636f8a9c18efeea22 2 889c8db9e97f1e240ae4488f3b34dd6efb086c3425d6f949a6056a0c06231585
snapshot 1.0.1 37bcec3118a244ff024e9d6f5d92806aeaa2fa0c 3 9872367ede865ddd204520a2880b506644d6ad22461d70c439de2bfc965797be

artifacts=$(cargo test --locked --manifest-path core/Cargo.toml --lib --no-run --message-format=json-render-diagnostics)
app_tests=$(jq -er 'select(.reason == "compiler-artifact" and .target.kind == ["lib"] and .profile.test) | .executable // empty' <<< "$artifacts")
artifacts=$(cargo build --locked --manifest-path core/Cargo.toml --bin rentnerproxy-controller --message-format=json-render-diagnostics)
controller=$(jq -er 'select(.reason == "compiler-artifact" and .target.name == "rentnerproxy-controller" and .target.kind == ["bin"]) | .executable // empty' <<< "$artifacts")
[[ -x $app_tests && -x $controller ]]

# The only catalog transport is a loopback TLS fixture. The app still uses the
# regular manager, a native sandboxed process and the appliance's PostgreSQL policy.
docker run --rm --init --no-healthcheck --network none --add-host github.com:127.0.0.1 --read-only --user 0:0 \
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add KILL \
    --cap-add SETGID --cap-add SETUID --cap-add NET_BIND_SERVICE --security-opt no-new-privileges \
    --tmpfs '/run:rw,exec,mode=0755,size=128m' \
    --tmpfs '/tmp:rw,exec,mode=01777,size=1024m' \
    --tmpfs '/var/lib/rentnerproxy:rw,exec,mode=0711,size=1024m' \
    --mount "type=bind,source=$app_tests,target=/app-tests,readonly" \
    --mount "type=bind,source=$controller,target=/controller,readonly" \
    --mount "type=bind,source=$work,target=/greeting,readonly" \
    --mount "type=bind,source=$fixture_script,target=/fixture/run.sh,readonly" \
    --mount "type=bind,source=$PWD/docker/production/apps/pg_hba.conf,target=/fixture/pg_hba.conf,readonly" \
    --mount "type=bind,source=$PWD/docker/production/apps/pg_ident.conf,target=/fixture/pg_ident.conf,readonly" \
    --mount "type=bind,source=$output,target=/evidence" \
    --env RENTNERPROXY_TEST_CONTROLLER=/controller --env RP_GREETING_FIXTURE=/greeting \
    --env RP_GREETING_LIFECYCLE_REPORT=/evidence/greeting-lifecycle.json \
    --entrypoint /bin/bash \
    ghcr.io/rentnerproxy/platform@sha256:fe320f29302a2253296b986962de9d3d84fd6f0abb788a414cc325ca424c74e3 \
    /fixture/run.sh --container
