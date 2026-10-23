-- Full SET-role closure; provider and Audit owners validate their own structural contracts.
WITH reachable AS MATERIALIZED (SELECT * FROM pg_roles WHERE pg_has_role($1::name,oid,'SET'))
SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1 AND rolcanlogin)
AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN pg_namespace n
 WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(r.oid,n.oid,'CREATE'))
AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname NOT IN ('information_schema','rss_transactional_messaging','rss_audit','rss_ledger') AND c.relkind IN ('r','p','v','m','f')
 AND (has_table_privilege(r.oid,c.oid,'INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
 OR has_any_column_privilege(r.oid,c.oid,'INSERT,REFERENCES')
 OR (n.nspname||'.'||c.relname NOT IN ('mdm_audit.receipts','mdm_audit.backlog') AND has_any_column_privilege(r.oid,c.oid,'SELECT,UPDATE'))
 OR (n.nspname='mdm_audit' AND has_table_privilege(r.oid,c.oid,'UPDATE'))))
AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_audit' AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(r.oid,c.oid,a.attnum,'UPDATE')
 AND NOT ((c.relname='receipts' AND a.attname='projected_at') OR (c.relname='backlog' AND a.attname IN ('events','bytes','reserved_events','reserved_bytes'))))
AND has_table_privilege($1,'mdm_audit.receipts','SELECT') AND has_table_privilege($1,'mdm_audit.backlog','SELECT')
AND has_column_privilege($1,'mdm_audit.receipts','projected_at','UPDATE')
AND NOT EXISTS(SELECT FROM pg_attribute WHERE attrelid='mdm_audit.backlog'::regclass AND attname IN ('events','bytes','reserved_events','reserved_bytes') AND NOT has_column_privilege($1,attrelid,attnum,'UPDATE'))
AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE (n.nspname LIKE 'mdm%' OR n.nspname='identity_authority' OR (n.nspname='rss_transactional_messaging' AND p.proname IN ('append_outbox','prepare_outbox_partitions')))
 AND p.prorettype NOT IN ('trigger'::regtype,'event_trigger'::regtype)
 AND has_schema_privilege(r.oid,n.oid,'USAGE') AND has_function_privilege(r.oid,p.oid,'EXECUTE'))
AND has_table_privilege($1,'rss_transactional_messaging.consumer_dead_letter','SELECT')
AND has_table_privilege($1,'rss_transactional_messaging.consumer_dead_letter','INSERT')
AND NOT EXISTS(SELECT FROM reachable r WHERE has_table_privilege(r.oid,'rss_transactional_messaging.consumer_dead_letter','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
 OR has_any_column_privilege(r.oid,'rss_transactional_messaging.consumer_dead_letter','UPDATE,REFERENCES'))
AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind='S' AND has_sequence_privilege(r.oid,c.oid,'USAGE,SELECT,UPDATE'))
