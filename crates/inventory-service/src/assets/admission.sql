WITH execution_roles AS (SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')),
reachable AS (SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))), tables AS (SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_assets' AND c.relkind='r' AND c.relname NOT IN('group_tasks','group_evaluations','group_evaluation_arrays','group_dispatch'))
SELECT
 current_setting('transaction_isolation')='read committed'
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['asset_query_facets','asset_query_results','asset_query_runs','field_layouts','group_fields','group_operations','group_selections','operations','query_evaluation_arrays','query_evaluations','saved_queries'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
 OR oid IN(SELECT relowner FROM tables))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR NOT has_table_privilege(current_user,t.oid,'INSERT')
 OR has_table_privilege(current_user,t.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_table_privilege(current_user,t.oid,'DELETE')<>(t.relname IN('group_fields','query_evaluation_arrays','query_evaluations'))
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <> ((t.relname='query_evaluations' AND a.attname='binding') OR (t.relname='query_evaluation_arrays' AND a.attname='state') OR (t.relname IN('saved_queries','field_layouts') AND a.attname IN('revision','document')) OR (t.relname='asset_query_runs' AND a.attname IN('total','matched','unknown','started','completed','failure','cursor')) OR (t.relname='asset_query_facets' AND a.attname='total') OR (t.relname='configuration_devices' AND a.attname='input_revision')) OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm.manual_assignments'::regclass AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)

 AND (SELECT jsonb_agg(jsonb_build_array(attname,format_type(atttypid,atttypmod),attnotnull) ORDER BY attnum)
 FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped) @> '[["tenant_id","uuid",true],["device","text",true],["field","text",true],["revision","bigint",true],["fact","jsonb",true],["value_version","text",false],["last_known_version","text",false]]'::jsonb
 AND (SELECT count(*)=4 AND bool_and(convalidated AND pg_get_constraintdef(oid)=CASE conname
 WHEN 'manual_assignments_field_check' THEN 'CHECK (((length(field) <= 128) AND (field ~ ''^(device|custom|channel)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$''::text)))'
 WHEN 'manual_assignments_revision_check' THEN 'CHECK ((revision > 0))'
 WHEN 'manual_value_representation' THEN 'CHECK (((((fact #>> ''{state,kind}''::text[]) = ''known''::text) = (((fact #> ''{state,value}''::text[]) IS NOT NULL) OR (value_version IS NOT NULL))) AND (NOT (((fact #> ''{state,value}''::text[]) IS NOT NULL) AND (value_version IS NOT NULL))) AND ((value_version IS NULL) OR ((fact #>> ''{state,kind}''::text[]) = ''known''::text)) AND ((last_known_version IS NULL) OR (((fact #> ''{lastKnown,evidence}''::text[]) IS NOT NULL) AND ((fact #> ''{lastKnown,value}''::text[]) IS NULL))) AND ((fact #>> ''{state,value,kind}''::text[]) IS DISTINCT FROM ''array''::text) AND ((fact #>> ''{lastKnown,value,kind}''::text[]) IS DISTINCT FROM ''array''::text)))'
 WHEN 'manual_assignments_fact_check' THEN 'CHECK ((octet_length((fact)::text) <= 16777216))' ELSE '' END)
 FROM pg_constraint WHERE conrelid=c.oid AND contype='c'
 AND conname IN('manual_assignments_field_check','manual_assignments_revision_check','manual_value_representation','manual_assignments_fact_check'))
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND has_column_privilege(current_user,c.oid,'revision','UPDATE') AND has_column_privilege(current_user,c.oid,'fact','UPDATE')
 AND (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)=1
 AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=c.oid AND contype='p' AND convalidated AND pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, device, field)')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND (has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(a.attname IN('revision','fact','value_version','last_known_version')) OR has_column_privilege(current_user,c.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c,LATERAL aclexplode(c.attacl) a WHERE c.attrelid='mdm.manual_assignments'::regclass AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 )

 -- Required cursor and fact representations used by the planning SQL readers.
 AND NOT EXISTS(SELECT 1 FROM (VALUES
 ('mdm_assets.query_evaluations','binding','text',true),
 ('mdm_assets.query_evaluation_arrays','state','jsonb',true),
 ('mdm.manual_assignments','fact','jsonb',true)
 ) required(relation,column_name,type_name,not_null) WHERE NOT EXISTS(
 SELECT 1 FROM pg_attribute a WHERE a.attrelid=to_regclass(required.relation)
 AND a.attname=required.column_name AND NOT a.attisdropped
 AND a.atttypid=to_regtype(required.type_name) AND (NOT required.not_null OR a.attnotnull)))

 -- Inventory checks references through the Resource reader without Resource write authority.
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_resource.field_refs'::regclass
  AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)
  AND has_table_privilege(current_user,c.oid,'SELECT'))
 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE
  has_table_privilege(r.oid,'mdm_resource.field_refs','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_any_column_privilege(r.oid,'mdm_resource.field_refs','INSERT,UPDATE,REFERENCES'))
