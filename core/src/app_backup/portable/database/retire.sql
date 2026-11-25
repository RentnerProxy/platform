-- A replacing restore drops only the app identities of installations that the
-- journal owns. Any other app database or role rejects it before changes.
WITH retiring AS (
    SELECT format('rp_app_%s', uid) AS app, format('rp_migrate_%s', uid) AS owner
    FROM unnest(:'uids'::integer[]) AS uid
)
SELECT NOT EXISTS (
    SELECT FROM pg_database d
    WHERE (starts_with(d.datname, 'rp_app_') OR starts_with(d.datname, 'rp_migrate_'))
      AND NOT EXISTS (SELECT FROM retiring r WHERE d.datname = r.app)
) AND NOT EXISTS (
    SELECT FROM pg_authid a
    WHERE (starts_with(a.rolname, 'rp_app_') OR starts_with(a.rolname, 'rp_migrate_'))
      AND NOT EXISTS (SELECT FROM retiring r WHERE a.rolname IN (r.app, r.owner))
);
