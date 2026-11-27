required_columns(schema_name, table_name, column_name) AS (
 SELECT 'mdm_access','command_authorities',unnest(ARRAY['tenant_id','device','command_device']) WHERE $2
 UNION ALL
 SELECT 'mdm_devices','retirement_work',unnest(ARRAY['tenant_id','execution','operation']) WHERE $4
), owner_relations AS (
 SELECT unnest($1::text[]) AS name
 UNION SELECT schema_name||'.'||table_name FROM required_columns
), checked_relations AS (
 SELECT c.oid, c.relrowsecurity AND c.relforcerowsecurity AS fenced,
 CASE r.name WHEN 'rss_da.access_runs' THEN '(da_target IS NULL)'
             WHEN 'rss_da.credential_runs' THEN '(da_execution IS NULL)' END AS agent_condition
 FROM owner_relations r LEFT JOIN pg_namespace n ON n.nspname=split_part(r.name,'.',1)
 LEFT JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=split_part(r.name,'.',2)
), effective_policies AS (
 SELECT p.polrelid, p.polcmd, p.polpermissive, p.polroles, p.polname,
 pg_get_expr(p.polqual,p.polrelid) AS predicate, pg_get_expr(p.polwithcheck,p.polrelid) AS checked
 FROM pg_policy p JOIN checked_relations c ON c.oid=p.polrelid
 WHERE p.polcmd IN ('*','r','w') AND p.polroles && (ARRAY[0::oid] ||
   ARRAY(SELECT r.oid FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'USAGE')))
)
SELECT NOT EXISTS (
 SELECT FROM checked_relations c WHERE c.oid IS NULL OR NOT c.fenced OR
 (SELECT count(*) FROM effective_policies p WHERE p.polrelid=c.oid) <> CASE WHEN c.agent_condition IS NULL THEN 1 ELSE 2 END
 OR NOT EXISTS(SELECT FROM effective_policies p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*'
   AND p.polpermissive AND p.polroles=ARRAY[0::oid] AND p.predicate=p.checked
   AND lower(replace(regexp_replace(p.predicate,'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid')
 OR (c.agent_condition IS NOT NULL AND NOT EXISTS(SELECT FROM effective_policies p WHERE p.polrelid=c.oid AND p.polcmd='*'
   AND NOT p.polpermissive AND p.predicate=c.agent_condition AND p.checked=c.agent_condition))
)
AND NOT EXISTS (
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
