WITH scope AS (
    SELECT n.oid, n.nspowner
    FROM pg_namespace n
    WHERE n.nspname = 'app' AND n.nspowner = :'owner'::regrole
      AND cardinality(n.nspacl) = 2
      AND n.nspacl @> ARRAY[format('%s=UC/%s', :'owner', :'owner')::aclitem,
                            format('%s=U/%s', :'role', :'owner')::aclitem]
), expected_defaults AS (
    SELECT 'r'::"char" AS kind, format('%s=arwd/%s', :'role', :'owner')::aclitem AS acl
    UNION ALL
    SELECT 'S'::"char", format('%s=rU/%s', :'role', :'owner')::aclitem
), grants AS (
    SELECT 'r'::"char" AS kind,
        ARRAY[format('%s=arwdDxtm/%s', :'owner', :'owner')::aclitem,
              format('%s=arwd/%s', :'role', :'owner')::aclitem] AS acl
    UNION ALL
    SELECT 'S'::"char",
        ARRAY[format('%s=rwU/%s', :'owner', :'owner')::aclitem,
              format('%s=rU/%s', :'role', :'owner')::aclitem]
)
SELECT EXISTS (SELECT FROM scope)
   AND EXISTS (
        SELECT FROM pg_namespace n WHERE nspname = 'public' AND nspowner = 'pg_database_owner'::regrole
          AND cardinality(n.nspacl) = 1 AND n.nspacl @> ARRAY['pg_database_owner=UC/pg_database_owner'::aclitem]
   )
   AND NOT EXISTS (
        SELECT FROM pg_namespace n WHERE n.oid >= 16384 AND n.nspname <> 'app'
   )
   AND NOT EXISTS (
        SELECT FROM pg_default_acl d
        WHERE NOT EXISTS (
            SELECT FROM scope n, expected_defaults e
            WHERE d.defaclnamespace = n.oid AND d.defaclrole = n.nspowner AND d.defaclobjtype = e.kind
              AND cardinality(d.defaclacl) = 1 AND d.defaclacl @> ARRAY[e.acl]
        )
   )
   AND (SELECT count(*) FROM pg_default_acl) = 2
   AND NOT EXISTS (
        SELECT FROM pg_class c JOIN scope n ON n.oid = c.relnamespace
        LEFT JOIN grants g ON g.kind = CASE WHEN c.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END
        WHERE c.relowner <> n.nspowner OR c.relpersistence <> 'p' OR c.reltablespace <> 0
          OR c.relkind NOT IN ('r', 'p', 'S', 'v', 'i', 'I', 'c')
          OR c.relrowsecurity OR c.relforcerowsecurity
          OR (c.relkind IN ('r', 'p', 'S', 'v')
              AND NOT coalesce(cardinality(c.relacl) = 2 AND c.relacl @> g.acl, false))
          OR EXISTS (SELECT FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attacl IS NOT NULL)
   )
   AND NOT EXISTS (
        SELECT FROM pg_proc p JOIN scope n ON n.oid = p.pronamespace
        WHERE p.proowner <> n.nspowner OR p.proacl IS NOT NULL
   )
   AND NOT EXISTS (
        SELECT FROM pg_type t JOIN scope n ON n.oid = t.typnamespace
        WHERE t.typowner <> n.nspowner OR t.typacl IS NOT NULL
   )
   AND NOT EXISTS (SELECT FROM pg_largeobject_metadata)
   AND NOT EXISTS (SELECT FROM pg_seclabel)
   AND NOT EXISTS (SELECT FROM pg_publication)
   AND NOT EXISTS (SELECT FROM pg_subscription WHERE subdbid = (SELECT oid FROM pg_database WHERE datname = current_database()))
   AND NOT EXISTS (SELECT FROM pg_extension WHERE oid >= 16384)
   AND NOT EXISTS (SELECT FROM pg_foreign_server)
   AND NOT EXISTS (SELECT FROM pg_foreign_data_wrapper)
   AND NOT EXISTS (SELECT FROM pg_event_trigger)
   AND (NOT :'pristine'::boolean OR NOT EXISTS (
        SELECT FROM pg_depend d JOIN scope n
            ON d.refclassid = 'pg_namespace'::regclass AND d.refobjid = n.oid
        WHERE d.classid <> 'pg_default_acl'::regclass
   ))
   AND (NOT :'pristine'::boolean OR NOT EXISTS (
        SELECT FROM pg_description d JOIN scope n
            ON d.classoid = 'pg_namespace'::regclass AND d.objoid = n.oid
   ));
