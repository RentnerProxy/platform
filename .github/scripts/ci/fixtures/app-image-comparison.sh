#!/usr/bin/env bash
set -euo pipefail

baseline=${1:?Expected the previous native image ID}
candidate=${2:?Expected the candidate native image ID}
[[ $baseline =~ ^sha256:[a-f0-9]{64}$ && $candidate =~ ^sha256:[a-f0-9]{64}$ ]]
native=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')
for image in "$baseline" "$candidate"; do
    [[ $(docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' "$image") == "$image $native" ]]
done

scope=rentnerproxy-image-comparison-$(cat /proc/sys/kernel/random/uuid)
reused="$scope-reused"
fresh="$scope-fresh"
container=
cleanup() {
    if [[ -n $container ]]; then docker rm --force --volumes "$container" >/dev/null 2>&1 || true; fi
    docker volume rm "$reused" "$fresh" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker volume create "$reused" >/dev/null
docker volume create "$fresh" >/dev/null

start() {
    local image=$1 data=$2 start_ms deadline
    container="$scope-appliance"
    start_ms=$(date +%s%3N)
    docker run --detach --pull=never --name "$container" --network none \
        --mount "type=volume,source=$data,target=/var/lib/rentnerproxy" \
        --env RENTNERPROXY_PUBLIC_ORIGIN=https://fixture.invalid \
        --env SMTP_FROM=fixture@fixture.invalid --env SMTP_HOST=127.0.0.1 \
        --env SMTP_PORT=2525 --env SMTP_SECURE=false \
        --env SMTP_USER=fixture --env SMTP_PASSWORD=synthetic-fixture \
        "$image" >/dev/null
    deadline=$((SECONDS + 120))
    until docker exec "$container" curl --fail --silent --max-time 2 \
        http://127.0.0.1:3000/health/ready >/dev/null 2>&1; do
        if (( SECONDS >= deadline )) || [[ $(docker inspect --format '{{.State.Running}}' "$container") != true ]]; then
            docker logs --tail 35 "$container" >&2
            return 1
        fi
        sleep 0.25
    done
    readiness_ms=$(( $(date +%s%3N) - start_ms ))
}

stop() {
    docker stop --time 35 "$container" >/dev/null
    [[ $(docker inspect --format '{{.State.ExitCode}}' "$container") == 0 ]]
    docker rm --volumes "$container" >/dev/null
    container=
}

measure() {
    local image=$1 bytes memory
    bytes=$(docker image inspect --format '{{.Size}}' "$image") || return 1
    sleep 2
    memory=$(docker exec "$container" cat /sys/fs/cgroup/memory.current) || return 1
    [[ $bytes =~ ^[0-9]+$ && $memory =~ ^[0-9]+$ ]] || return 1
    printf '%s | %s | %s' "$bytes" "$readiness_ms" "$memory"
}

query() {
    docker exec "$container" gosu postgres psql --no-psqlrc --no-password \
        --host=/var/run/postgresql --username=postgres --dbname=rentnerproxy \
        --tuples-only --no-align --quiet --set=ON_ERROR_STOP=1 --command="$1"
}

require_incompatible_startup() {
    local reason=$1
    if start "$candidate" "$reused"; then
        echo 'The Alpine candidate started with an incompatible collation' >&2
        exit 1
    fi
    docker logs "$container" 2>&1 | grep -F "$reason"
    docker rm --volumes "$container" >/dev/null
    container=
}

require_icu_upgrade_rejection() {
    local setup=$1 cleanup=$2
    query "$setup $unicode_version;"
    stop
    require_incompatible_startup 'PostgreSQL object collation changed'
    start "$baseline" "$reused"
    query "$cleanup $restore_unicode;"
}

start "$baseline" "$reused"
before=$(measure "$baseline")
baseline_os=$(docker exec "$container" cat /etc/os-release)
system_id=$(query 'SELECT system_identifier FROM pg_control_system()')
query "
    CREATE ROLE image_comparison_reader NOLOGIN;
    CREATE TABLE image_comparison_fixture (id integer PRIMARY KEY, greeting jsonb);
    INSERT INTO image_comparison_fixture VALUES (1, '{\"message\":\"original\"}');
    GRANT SELECT ON image_comparison_fixture TO image_comparison_reader;
"
read_rows="SET ROLE image_comparison_reader; SELECT string_agg(greeting->>'message', ',' ORDER BY id) FROM image_comparison_fixture"
stop

start "$candidate" "$reused"
[[ $(query 'SELECT system_identifier FROM pg_control_system()') == "$system_id" ]]
[[ $(query "$read_rows") == original ]]
query "INSERT INTO image_comparison_fixture VALUES (2, '{\"message\":\"upgraded\"}')"
stop

start "$baseline" "$reused"
[[ $(query 'SELECT system_identifier FROM pg_control_system()') == "$system_id" ]]
[[ $(query "$read_rows") == original,upgraded ]]
stop

start "$candidate" "$fresh"
after=$(measure "$candidate")
candidate_os=$(docker exec "$container" cat /etc/os-release)
stop

if grep -qx 'ID=debian' <<< "$baseline_os" && grep -qx 'ID=alpine' <<< "$candidate_os"; then
    # Alter only the recorded ICU version in this disposable cluster. This
    # exercises the upgrade guard even when the two package builds use equal ICU.
    unicode_version="UPDATE pg_catalog.pg_collation SET collversion = 'comparison-stale-icu' WHERE oid = 'pg_catalog.\"unicode\"'::regcollation"
    restore_unicode="UPDATE pg_catalog.pg_collation SET collversion = pg_collation_actual_version(oid) WHERE oid = 'pg_catalog.\"unicode\"'::regcollation"
    start "$baseline" "$reused"
    query "CREATE TABLE image_comparison_text (value text); INSERT INTO image_comparison_text VALUES ('z');"
    require_icu_upgrade_rejection '
        CREATE INDEX image_comparison_nested ON image_comparison_text ((lower(value COLLATE pg_catalog."unicode") COLLATE "C"));
    ' 'DROP INDEX image_comparison_nested;'

    require_icu_upgrade_rejection "
        CREATE FUNCTION image_comparison_unicode(value text) RETURNS boolean
        LANGUAGE sql IMMUTABLE SET search_path = pg_catalog
        AS \$\$ SELECT value COLLATE pg_catalog.\"unicode\" < 'z' \$\$;
        CREATE INDEX image_comparison_indirect ON image_comparison_text (image_comparison_unicode(value));
    " 'DROP INDEX image_comparison_indirect; DROP FUNCTION image_comparison_unicode(text);'

    require_icu_upgrade_rejection '
        CREATE DOMAIN image_comparison_icu_text AS text COLLATE pg_catalog."unicode" CHECK (length(VALUE) <= 16);
        CREATE INDEX image_comparison_domain ON image_comparison_text ((lower(value::image_comparison_icu_text) COLLATE "C"));
    ' 'DROP INDEX image_comparison_domain; DROP DOMAIN image_comparison_icu_text;'

    require_icu_upgrade_rejection "
        CREATE TYPE image_comparison_icu_range AS RANGE (subtype = text, collation = pg_catalog.\"unicode\");
        CREATE TABLE image_comparison_ranges (value image_comparison_icu_range);
        INSERT INTO image_comparison_ranges VALUES ('[a,z)');
        CREATE INDEX image_comparison_range ON image_comparison_ranges (value);
    " 'DROP TABLE image_comparison_ranges; DROP TYPE image_comparison_icu_range;'

    # The libc version reported for LC_COLLATE=C cannot prove LC_CTYPE compatibility.
    query 'DROP TABLE image_comparison_text;'
    query "CREATE DATABASE image_comparison_locale TEMPLATE template0 LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'en_US.utf8'"
    stop
    require_incompatible_startup 'PostgreSQL database collation is incompatible or a database is unavailable'
fi

{
    printf '## Platform appliance comparison (%s)\n\n' "$native"
    printf '| Build | Image bytes | Fresh-volume readiness (ms) | Cgroup memory bytes after 2 s idle |\n'
    printf '| --- | ---: | ---: | ---: |\n'
    printf '| Previous | %s |\n| Candidate | %s |\n\n' "$before" "$after"
    printf 'Same native runner, one fresh-volume sample per build. The original cluster, JSONB rows and role grant survived upgrade and rollback.\n'
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
