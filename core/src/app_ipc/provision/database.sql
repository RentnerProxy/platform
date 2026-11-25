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
-- An interrupted data migration may have left the runtime role able to assume the schema owner.
REVOKE :"migration_role" FROM :"role";
SELECT format('CREATE DATABASE %I OWNER postgres', :'role') WHERE NOT EXISTS
    (SELECT FROM pg_database WHERE datname = :'role')
\gexec
REVOKE ALL ON DATABASE :"role" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"role" TO :"role";
ALTER ROLE :"role" IN DATABASE :"role" SET search_path TO app;
ALTER ROLE :"role" IN DATABASE :"role" SET statement_timeout TO '10s';
ALTER ROLE :"role" IN DATABASE :"role" SET idle_in_transaction_session_timeout TO '15s';
