#!/usr/bin/env bash
set -Eeuo pipefail

readonly controller=${RENTNERPROXY_TEST_CONTROLLER:-/controller}
readonly ipc_tests=${RENTNERPROXY_TEST_IPC_BINARY:-/ipc-tests}
readonly appliance=/var/lib/rentnerproxy
readonly apps="$appliance/apps"
readonly bootstrap="$appliance/bootstrap"
readonly postgres=/usr/lib/postgresql/18/bin
readonly socket=/var/run/postgresql
readonly database=/tmp/app-provision-postgres

[[ $(id -u) == 0 && -x $controller && -x $ipc_tests && ! -e $apps && ! -e $bootstrap && ! -e $database ]]

reject() {
    if "$@" >/dev/null 2>&1; then
        printf 'Unexpected success for %s\n' "$2" >&2
        exit 1
    fi
}

provision() { "$controller" --app-provision "$@"; }
state() { "$controller" --write-bootstrap-state "$@"; }
query() {
    gosu postgres "$postgres/psql" --no-psqlrc --no-password --quiet --tuples-only --no-align \
        --set=ON_ERROR_STOP=1 --host="$socket" --username=postgres "$@"
}

reject "$controller" --app-provision
reject "$controller" --app-provision last1
reject "$controller" --app-provision 19999
reject "$controller" --app-provision 60000
reject "$controller" --app-provision 59180 other
reject "$controller" --app-provision 59180 files extra
"$controller" --app-backup empty
captured=$("$controller" --app-backup capture)
[[ -z $captured ]]
reject "$controller" --app-backup unknown
reject "$controller" --app-backup inspect /tmp/missing-snapshot
reject "$controller" --app-manager
reject "$controller" --app-manager /tmp/missing-config extra
printf '{"version":1,"connections":[]}' | "$controller" --check-backup-state dns-registry
printf '{"version":2,"connections":[]}' | reject "$controller" --check-backup-state dns-registry
printf '{"certificates":{}}' | "$controller" --check-backup-state certificate-index
reject "$controller" --check-backup-state other
provision 59180
provision 59180 files
[[ $(stat -c '%u:%g:%a' "$apps" "$apps/59180" "$apps/59180/data") == $'0:0:711\n0:59180:710\n59180:59180:700' ]]
[[ ! -e $apps/59180/database-password && ! -e $apps/59180/data/database-url ]]
reject "$controller" --app-backup capture

ln -s "$apps/59180" "$apps/59181"
reject "$controller" --app-provision 59181 files
rm "$apps/59181"
install -d -m 0755 "$apps/59181"
reject "$controller" --app-provision 59181 files
rmdir "$apps/59181"
provision 59181
ln "$apps/59181/.provision.lock" "$apps/59181/alias"
reject "$controller" --app-provision 59181 files
rm "$apps/59181/alias"

# First try without a running cluster. The retry must retain the reserved credential.
reject "$controller" --app-provision 59182 database
readonly credential="$apps/59182/database-password"
[[ $(stat -c '%u:%g:%a:%h:%s' "$credential") == 0:0:600:1:65 && ! -e $apps/59182/data/database-url ]]
fingerprint=$(sha256sum "$credential")

install -d -m 0700 -o postgres -g postgres "$database"
install -d -m 0755 -o postgres -g postgres "$socket"
gosu postgres "$postgres/initdb" --pgdata="$database" --auth-local=trust --auth-host=reject >/dev/null
gosu postgres "$postgres/pg_ctl" --pgdata="$database" --log="$database/server.log" \
    --options="-c listen_addresses= -c unix_socket_directories=$socket" --wait --timeout=15 start >/dev/null
trap 'gosu postgres "$postgres/pg_ctl" --pgdata="$database" --mode=immediate --wait --timeout=15 stop >/dev/null' EXIT

provision 59182 database
chmod 0400 "$credential"
provision 59182 database
[[ $(sha256sum "$credential") == "$fingerprint" ]]
[[ $(stat -c '%u:%g:%a:%h' "$apps/59182/data/database-url") == 59182:59182:400:1 ]]
[[ $(query --dbname=postgres -c "SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND rolconnlimit=4 FROM pg_roles WHERE rolname='rp_app_59182'") == t ]]
[[ $(query --dbname=rp_app_59182 -c "SELECT nspowner::regrole='rp_migrate_59182'::regrole AND has_schema_privilege('rp_app_59182', 'app', 'USAGE') AND NOT has_schema_privilege('rp_app_59182', 'app', 'CREATE') FROM pg_namespace WHERE nspname='app'") == t ]]
provision 59183
install -m 0600 /dev/null "$apps/59183/database-password"
provision 59183 database
[[ $(stat -c '%s' "$apps/59183/database-password") == 65 ]]
printf 'invalid\n' > "$apps/59183/database-password"
reject "$controller" --app-provision 59183 database
chmod 0644 "$apps/59183/database-password"
reject "$controller" --app-provision 59183 database

readonly state_file="$bootstrap/production-restore-v1.json"
reject "$controller" --write-bootstrap-state production-restore-v1.json create
install -d -m 0755 "$bootstrap"
reject "$controller" --write-bootstrap-state production-restore-v1.json create
chmod 0700 "$bootstrap"
reject "$controller" --write-bootstrap-state ../outside create
reject "$controller" --write-bootstrap-state production-restore-v1.json other
reject "$controller" --write-bootstrap-state production-restore-v1.json create extra
reject "$controller" --write-bootstrap-state production-restore-v1.json create </dev/null
reject "$controller" --write-bootstrap-state production-restore-v1.json create </dev/zero
printf '{}' | state production-restore-v1.json create
[[ $(stat -c '%u:%g:%a:%h' "$state_file") == 0:0:400:1 ]]
printf '{}' | reject "$controller" --write-bootstrap-state production-restore-v1.json create
printf '{"fixture":true}' | state production-restore-v1.json replace
[[ $(<"$state_file") == '{"fixture":true}' ]]
ln "$state_file" "$bootstrap/alias"
printf '{}' | reject "$controller" --write-bootstrap-state production-restore-v1.json replace
rm "$bootstrap/alias"
mv "$state_file" "$bootstrap/sentry"
ln -s "$bootstrap/sentry" "$state_file"
printf '{}' | reject "$controller" --write-bootstrap-state production-restore-v1.json replace
[[ $(<"$bootstrap/sentry") == '{"fixture":true}' ]]
"$ipc_tests" --ignored --exact app_manager::tests::privileged_postgres_uid_fencing
printf '%s\n' 'PASS: native app UID and PostgreSQL provisioning and protected bootstrap publication'
