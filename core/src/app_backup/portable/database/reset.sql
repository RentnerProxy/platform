-- The caller has durably reserved this UID against an empty target, or the journal
-- owns it and the portable restore marker records its retirement. Without `apply`,
-- only check that the identities could be dropped.
WITH roles AS (
    SELECT r.* FROM pg_authid r WHERE r.rolname IN (:'role', :'owner')
), target AS (
    SELECT d.* FROM pg_database d WHERE d.datname = :'role'
)
SELECT 1 / (
    NOT EXISTS (
        SELECT FROM roles r WHERE
            r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
            OR (r.rolname = :'owner' AND (r.rolcanlogin OR r.rolpassword IS NOT NULL))
    )
    AND NOT EXISTS (
        SELECT FROM target d
        WHERE d.datdba <> 'postgres'::regrole OR d.datistemplate OR NOT d.datallowconn
          OR EXISTS (
              SELECT FROM aclexplode(d.datacl) a
              WHERE a.grantor <> d.datdba OR a.is_grantable
                OR NOT coalesce(a.grantee = d.datdba OR
                    (a.grantee = (SELECT oid FROM roles WHERE rolname = :'role')
                     AND a.privilege_type = 'CONNECT'), false)
          )
    )
    AND NOT EXISTS (
        SELECT FROM pg_auth_members m
        WHERE (m.roleid IN (SELECT oid FROM roles) OR m.member IN (SELECT oid FROM roles) OR m.grantor IN (SELECT oid FROM roles))
          AND NOT coalesce(m.roleid = (SELECT oid FROM roles WHERE rolname = :'owner')
                   AND m.member = (SELECT oid FROM roles WHERE rolname = :'role')
                   AND m.grantor = 'postgres'::regrole
                   AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option, false)
    )
    AND NOT EXISTS (
        SELECT FROM pg_shdepend d
        WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid IN (SELECT oid FROM roles)
          AND d.dbid NOT IN (SELECT oid FROM target)
          AND NOT coalesce(d.dbid = 0 AND d.classid = 'pg_database'::regclass AND d.objid IN (SELECT oid FROM target)
                   AND d.deptype = 'a' AND d.refobjid = (SELECT oid FROM roles WHERE rolname = :'role'), false)
    )
    AND NOT EXISTS (
        SELECT FROM pg_db_role_setting s WHERE s.setrole IN (SELECT oid FROM roles)
          AND s.setdatabase NOT IN (SELECT oid FROM target)
    )
    AND NOT EXISTS (
        SELECT FROM pg_prepared_xacts WHERE database = :'role' OR owner IN (:'role', :'owner')
    )
)::int;

\if :apply
SELECT format('ALTER ROLE %I NOLOGIN', rolname) FROM pg_roles WHERE rolname IN (:'role', :'owner')
\gexec
SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity WHERE usename IN (:'role', :'owner');
SELECT 1 / (NOT EXISTS (SELECT FROM pg_stat_activity WHERE usename IN (:'role', :'owner')))::int;
DROP DATABASE IF EXISTS :"role";
BEGIN;
DROP ROLE IF EXISTS :"role";
DROP ROLE IF EXISTS :"owner";
COMMIT;
\endif
