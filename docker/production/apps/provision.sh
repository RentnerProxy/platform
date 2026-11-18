#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

fail() {
    printf '%s\n' '[app-runtime] could not provision the installation identity' >&2
    exit 1
}

# Called by the trusted appliance manager with the UID recorded for this installation.
[[ $(id -u) == 0 && $# -ge 1 && $# -le 2 && $1 =~ ^[2-5][0-9]{4}$ ]] || fail
readonly uid=$1
readonly storage=${2:-files}
[[ $storage == files || $storage == database ]] || fail

readonly apps=/var/lib/rentnerproxy/apps
readonly installation="$apps/$uid"
readonly data="$installation/data"
[[ ! -L $apps && ! -L $installation && ! -L $data ]] || fail
install -d -m 0711 -o root -g root -- "$apps"
install -d -m 0710 -o root -g "$uid" -- "$installation"
exec {provision_lock}>"$installation/.provision.lock"
flock --exclusive "$provision_lock"
install -d -m 0700 -o "$uid" -g "$uid" -- "$data"
[[ $storage == database ]] || exit 0

readonly role="rp_app_$uid"
readonly migration_role="rp_migrate_$uid"
readonly password_path="$installation/database-password"
temporary=''
trap 'if [[ -n $temporary ]]; then rm -f -- "$temporary"; fi' EXIT
password=''
if [[ -e $password_path || -L $password_path ]]; then
    [[ -f $password_path && ! -L $password_path ]] || fail
    [[ $(stat -c '%u:%h:%a' -- "$password_path") =~ ^0:1:[46]00$ ]] || fail
    password=$(<"$password_path")
fi
if [[ ! $password =~ ^[0-9a-f]{64}$ ]]; then
    temporary=$(mktemp "$installation/.database-password.XXXXXXXX")
    openssl rand -hex 32 >"$temporary"
    password=$(<"$temporary")
    [[ $password =~ ^[0-9a-f]{64}$ ]] || fail
    mv -Tf -- "$temporary" "$password_path"
    temporary=''
fi

psql() {
    gosu postgres /usr/lib/postgresql/18/bin/psql --no-psqlrc --no-password --quiet \
        --host=/var/run/postgresql --username=postgres --set=ON_ERROR_STOP=1 \
        --set=VERBOSITY=terse --set=role="$role" --set=migration_role="$migration_role" "$@"
}

# Use a distinct NOLOGIN migration owner. The app login receives only data access in its own schema.
if ! RENTNERPROXY_APP_DATABASE_PASSWORD=$password psql --dbname=postgres >/dev/null 2>&1 <<'SQL'
SET log_statement='none';
SET log_min_duration_statement=-1;
SET log_min_duration_sample=-1;
SET log_transaction_sample_rate=0;
SET log_min_error_statement='panic';
SET password_encryption='scram-sha-256';
SELECT format('CREATE ROLE %I', :'role') WHERE NOT EXISTS
    (SELECT FROM pg_roles WHERE rolname = :'role')
\gexec
SELECT format('CREATE ROLE %I', :'migration_role') WHERE NOT EXISTS
    (SELECT FROM pg_roles WHERE rolname = :'migration_role')
\gexec
\getenv app_password RENTNERPROXY_APP_DATABASE_PASSWORD
ALTER ROLE :"role" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 4 PASSWORD :'app_password';
\unset app_password
ALTER ROLE :"migration_role" WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
SELECT format('CREATE DATABASE %I OWNER postgres', :'role') WHERE NOT EXISTS
    (SELECT FROM pg_database WHERE datname = :'role')
\gexec
REVOKE ALL ON DATABASE :"role" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"role" TO :"role";
ALTER ROLE :"role" IN DATABASE :"role" SET search_path TO app;
ALTER ROLE :"role" IN DATABASE :"role" SET statement_timeout TO '10s';
ALTER ROLE :"role" IN DATABASE :"role" SET idle_in_transaction_session_timeout TO '15s';
SQL
then
    fail
fi

if ! psql --dbname="$role" >/dev/null 2>&1 <<'SQL'
BEGIN;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION :"migration_role";
REVOKE ALL ON SCHEMA app FROM PUBLIC;
GRANT USAGE ON SCHEMA app TO :"role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO :"role";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO :"role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migration_role" IN SCHEMA app
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migration_role" IN SCHEMA app
    GRANT USAGE, SELECT ON SEQUENCES TO :"role";
COMMIT;
SQL
then
    fail
fi

# Publish the app's file atomically from outside its writable subtree.
temporary=$(mktemp "$installation/.database-url.XXXXXXXX")
printf 'postgresql://%s:%s@localhost/%s?socket=/run/rentnerproxy/app-db&max=4\n' \
    "$role" "$password" "$role" >"$temporary"
unset password
chown "$uid:$uid" -- "$temporary"
chmod 0400 -- "$temporary"
mv -Tf -- "$temporary" "$data/database-url"
temporary=''
