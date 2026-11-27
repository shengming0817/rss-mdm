required_columns(schema_name, table_name, column_name) AS (
 SELECT 'mdm_access','command_authorities',unnest(ARRAY['tenant_id','device','command_device']) WHERE $2
 UNION ALL
 SELECT 'mdm_devices','retirement_work',unnest(ARRAY['tenant_id','execution','operation']) WHERE $4
)
SELECT NOT EXISTS (
 SELECT FROM unnest($1::text[]) AS t(name)
 LEFT JOIN pg_namespace n ON n.nspname=split_part(t.name,'.',1)
 LEFT JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=split_part(t.name,'.',2)
 LEFT JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='gateway_accepted' AND NOT a.attisdropped
 WHERE a.attnum IS NULL OR c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
 OR NOT has_schema_privilege(current_user,n.oid,'USAGE')
 OR NOT has_table_privilege(current_user,c.oid,'SELECT')
 OR NOT has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')
 OR c.oid NOT IN (SELECT relation FROM command_initial_state)
)
AND NOT EXISTS (
 SELECT FROM required_columns r
 LEFT JOIN pg_namespace n ON n.nspname=r.schema_name
 LEFT JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=r.table_name
 LEFT JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname=r.column_name AND NOT a.attisdropped
 WHERE a.attnum IS NULL OR NOT has_schema_privilege(current_user,n.oid,'USAGE')
 OR NOT has_column_privilege(current_user,c.oid,a.attnum,'SELECT')
)
AND (NOT $2 OR coalesce(has_function_privilege(current_user,to_regprocedure('public.mdm_dispatch_native_status(uuid,text,text,bytea)'),'EXECUTE'),false))
AND (NOT $3 OR coalesce(has_function_privilege(current_user,to_regprocedure('public.mdm_dispatch_collection_wake(uuid,bytea)'),'EXECUTE'),false))
