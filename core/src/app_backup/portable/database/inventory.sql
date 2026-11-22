WITH expected AS (
    SELECT format('rp_app_%s', uid) AS app, format('rp_migrate_%s', uid) AS owner
    FROM unnest(:'uids'::integer[]) AS uid
), pairs AS (
    SELECT e.*, a.oid AS app_oid, m.oid AS owner_oid, d.oid AS db_oid
    FROM expected e
    JOIN pg_authid a ON a.rolname = e.app
    JOIN pg_authid m ON m.rolname = e.owner
    JOIN pg_database d ON d.datname = e.app
    WHERE NOT (a.rolsuper OR a.rolinherit OR a.rolcreaterole OR a.rolcreatedb OR a.rolreplication OR a.rolbypassrls)
      AND NOT (m.rolsuper OR m.rolinherit OR m.rolcreaterole OR m.rolcreatedb OR m.rolcanlogin OR m.rolreplication OR m.rolbypassrls)
      AND a.rolconnlimit = 4 AND m.rolconnlimit = -1
      AND (NOT :'fenced'::boolean OR NOT a.rolcanlogin)
      AND a.rolpassword LIKE 'SCRAM-SHA-256$%' AND m.rolpassword IS NULL
      AND (a.rolvaliduntil IS NULL OR a.rolvaliduntil = 'infinity'::timestamptz)
      AND m.rolvaliduntil IS NULL
      AND d.datdba = 'postgres'::regrole AND d.datallowconn AND NOT d.datistemplate
      AND d.dattablespace = (SELECT oid FROM pg_tablespace WHERE spcname = 'pg_default')
      AND d.datconnlimit = -1 AND pg_encoding_to_char(d.encoding) = 'UTF8'
      AND d.datlocprovider = 'c' AND d.datcollate = 'C' AND d.datctype = 'C'
      AND d.datlocale IS NULL AND d.daticurules IS NULL
      AND cardinality(d.datacl) = 2
      AND d.datacl @> ARRAY['postgres=CTc/postgres'::aclitem, format('%s=c/postgres', e.app)::aclitem]
)
SELECT (SELECT count(*) FROM expected) = (SELECT count(*) FROM pairs)
   AND (NOT :'exact'::boolean OR NOT EXISTS (
        SELECT FROM pg_database d
        WHERE (starts_with(d.datname, 'rp_app_') OR starts_with(d.datname, 'rp_migrate_'))
          AND NOT EXISTS (SELECT FROM pairs p WHERE p.db_oid = d.oid)
   ))
   AND (NOT :'exact'::boolean OR NOT EXISTS (
        SELECT FROM pg_authid r
        WHERE (starts_with(r.rolname, 'rp_app_') OR starts_with(r.rolname, 'rp_migrate_'))
          AND NOT EXISTS (SELECT FROM pairs p WHERE r.oid IN (p.app_oid, p.owner_oid))
   ))
   AND NOT EXISTS (
        SELECT FROM pairs p JOIN pg_auth_members m ON
            m.roleid IN (p.app_oid, p.owner_oid) OR m.member IN (p.app_oid, p.owner_oid)
            OR m.grantor IN (p.app_oid, p.owner_oid)
   )
   AND NOT EXISTS (
        SELECT FROM pairs p JOIN pg_shdepend s ON
            s.refclassid = 'pg_authid'::regclass AND s.refobjid IN (p.app_oid, p.owner_oid)
        WHERE s.dbid <> p.db_oid
          AND NOT (s.dbid = 0 AND s.classid = 'pg_database'::regclass AND s.objid = p.db_oid
                   AND s.deptype = 'a' AND s.refobjid = p.app_oid)
   )
   AND NOT EXISTS (
        SELECT FROM pairs p JOIN pg_db_role_setting s ON
            s.setdatabase = p.db_oid OR s.setrole IN (p.app_oid, p.owner_oid)
        WHERE NOT (s.setdatabase = p.db_oid AND s.setrole = p.app_oid
            AND cardinality(s.setconfig) = 3
            AND s.setconfig @> ARRAY['search_path=app', 'statement_timeout=10s', 'idle_in_transaction_session_timeout=15s'])
   )
   AND NOT EXISTS (
        SELECT FROM pairs p WHERE NOT EXISTS (
            SELECT FROM pg_db_role_setting s WHERE s.setdatabase = p.db_oid AND s.setrole = p.app_oid
        )
   )
   AND NOT EXISTS (
        SELECT FROM pairs p JOIN pg_stat_activity s
            ON s.usename IN (p.app, p.owner) OR (s.datid = p.db_oid AND s.backend_type <> 'autovacuum worker')
   )
   AND NOT EXISTS (
        SELECT FROM pairs p JOIN pg_prepared_xacts x ON x.database = p.app OR x.owner IN (p.app, p.owner)
   )
   AND NOT EXISTS (
        SELECT FROM pairs p JOIN pg_shdescription s ON
            (s.classoid = 'pg_database'::regclass AND s.objoid = p.db_oid)
            OR (s.classoid = 'pg_authid'::regclass AND s.objoid IN (p.app_oid, p.owner_oid))
   )
   AND NOT EXISTS (
        SELECT FROM pairs p JOIN pg_shseclabel s ON
            (s.classoid = 'pg_database'::regclass AND s.objoid = p.db_oid)
            OR (s.classoid = 'pg_authid'::regclass AND s.objoid IN (p.app_oid, p.owner_oid))
   );
