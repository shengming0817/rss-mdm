-- Product Ledger profile. Effective privileges include PUBLIC, inheritance and SET-only roles.
-- ref: PostgreSQL 18 src/backend/utils/adt/acl.c (has_*_privilege / pg_has_role).
WITH reachable AS (
    SELECT oid FROM pg_roles WHERE pg_has_role($1::name, oid, 'SET')
), allowed_functions AS (
    SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='rss_ledger' AND
        (p.proname, pg_catalog.oidvectortypes(p.proargtypes)) IN (
            ('prepare_append','uuid, text, text, smallint'),
            ('insert_entry','uuid, text, text, bigint, bytea, bytea, bytea, text, smallint')
        )
)
SELECT
    NOT EXISTS (
        SELECT FROM reachable r CROSS JOIN pg_namespace n WHERE n.nspname='rss_ledger'
        AND (has_schema_privilege(r.oid,n.oid,'CREATE,USAGE WITH GRANT OPTION')
             OR (NOT $2 AND has_schema_privilege(r.oid,n.oid,'USAGE')))
    )
    AND NOT EXISTS (
        SELECT FROM reachable r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='rss_ledger' AND c.relkind IN ('r','p','v','m','f')
        AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN,SELECT WITH GRANT OPTION')
             OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES,SELECT WITH GRANT OPTION')
             OR ((NOT $2 OR c.relname NOT IN ('heads','entries'))
                 AND has_any_column_privilege(r.oid,c.oid,'SELECT')))
    )
    AND NOT EXISTS (
        SELECT FROM reachable r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='rss_ledger' AND c.relkind='S'
        AND has_sequence_privilege(r.oid,c.oid,'USAGE,SELECT,UPDATE')
    )
    AND NOT EXISTS (
        SELECT FROM reachable r CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='rss_ledger'
        AND (has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION')
             OR ((NOT $2 OR p.oid NOT IN (SELECT oid FROM allowed_functions))
                 AND has_function_privilege(r.oid,p.oid,'EXECUTE')))
    )
    AND (NOT $2 OR (
        has_schema_privilege($1::name,'rss_ledger','USAGE')
        AND (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='rss_ledger' AND c.relname IN ('heads','entries')
             AND has_table_privilege($1::name,c.oid,'SELECT')) = 2
        AND (SELECT count(*) FROM allowed_functions) = 2
        AND NOT EXISTS (SELECT FROM allowed_functions WHERE NOT has_function_privilege($1::name,oid,'EXECUTE'))
    ))
