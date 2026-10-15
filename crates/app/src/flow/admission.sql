WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN('mdm_planning','mdm_flow','mdm_assets','mdm_automation','mdm_resource_catalog','mdm_publication') AND c.relkind='r'
), reachable AS (
 SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'MEMBER')
), package_execution_roles AS (
 -- SET ROLE is authorized against the original login, then inherits that role's privileges.
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')
), package_reachable AS (
 SELECT r.* FROM pg_roles r WHERE EXISTS(
  SELECT 1 FROM package_execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))
)
SELECT
 current_setting('transaction_isolation')='read committed'
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['asset_dispatch','asset_query_facets','asset_query_results','asset_query_runs','automation_jobs','configuration_claims','configuration_devices','configuration_objects','cursor_keys','group_fields','group_operations','group_selections','native_protection','operations','operations','operations','operations','policy_assignments','policy_source_grants','remote_operation_targets','remote_operations','saved_queries','scope_channel_results','scope_results','scope_runs','scope_source_members','scope_sources','scope_versions','scopes','source_heads'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
 OR oid IN(SELECT relowner FROM tables))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR has_table_privilege(current_user,t.oid,'INSERT')<>(t.relname NOT IN('configuration_claims','configuration_objects','remote_operation_targets','remote_operations'))
 OR has_table_privilege(current_user,t.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_table_privilege(current_user,t.oid,'DELETE')<>(t.relname IN('group_fields','scope_sources'))
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <> ((t.relname='source_heads' AND a.attname IN('revision','required_input','observed_input')) OR (t.relname='scopes' AND a.attname IN('revision','deleted','resolution','resolution_revision','calculation_revision','agent_resolution_revision','mdm_resolution_revision')) OR (t.relname='saved_queries' AND a.attname IN('revision','document')) OR (t.relname='automation_jobs' AND a.attname IN('forwarded','completed','failure','failure_detail','cursor','authority_revision','replacement_task')) OR (t.relname='asset_query_runs' AND a.attname IN('total','matched','unknown')) OR (t.relname='asset_query_facets' AND a.attname='total') OR (t.relname='asset_dispatch' AND a.attname IN('consumed','watermark','cursor','phase','failure','failure_generation','relation_after','relation_through','relation_cursor','relation_page_after','relation_page_through')) OR (t.relname='scope_runs' AND a.attname IN('phase','source_index','source_cursor','evaluation_cursor','projection_cursor','channel_hashes','object_count','member_count','identity_revision','result_fingerprint','previous_resolution','semantic_changed')) OR (t.relname='scope_channel_results' AND a.attname IN('matched','pending','target','entry_revision')) OR (t.relname='configuration_devices' AND a.attname='input_revision') OR (t.relname='policy_assignments' AND a.attname IN('input','availability','reason','target','scope_result','entry_revision'))) OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(current_user,n.oid,'CREATE'))
 AND has_schema_privilege(current_user,'mdm_planning','USAGE')
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN('r','v','m','f')
 AND n.nspname NOT IN('mdm_planning','mdm_flow','mdm_assets','mdm_automation','mdm_resource_catalog','mdm_publication','mdm_software','mdm_content','mdm_group','mdm_policy','mdm_resource','mdm_compliance')
 AND (n.nspname,c.relname) NOT IN(('mdm_devices','associations'),('mdm_devices','members'),('mdm_devices','checkpoints'),('mdm_devices','input_snapshots'),('mdm_devices','input_objects'),('public','mdm_installation'),('mdm_agent_packages','releases'),('mdm_apple','devices'),('mdm_apple','channels'),('mdm_agent','bindings'),('mdm_access','authorization_rules'),('mdm_access','user_groups'),('mdm_commands','capabilities'),('mdm_commands','operations'),('mdm','field_versions'),('mdm','collection_definitions'),('mdm','asset_clock'),('mdm','asset_changes'),('mdm','inventory_history'),('mdm','manual_history'),('mdm_access','asset_authority_history'),('mdm_access','collection_history'),('rss_reconcile','targets'),('rss_audit','heads'),('rss_audit','records'),('rss_ledger','heads'),('rss_ledger','entries'),('mdm_audit','receipts'),('mdm_access','devices'),('mdm_access','registrations'),('mdm_access','report_sources'),('mdm_access','collection_runs'),('mdm','inventory'),('mdm','manual_assignments'),('mdm_access','credentials'),('mdm_software_composition','subjects'),('mdm_software_composition','targets'),('mdm_software_composition','projections'),('mdm_software_release','aggregates'),('rss_transactional_messaging','policy'),('rss_transactional_messaging','outbox'))
 AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname,c.relname) IN(('mdm_devices','associations'),('mdm_devices','members'),('mdm_devices','checkpoints'),('mdm_agent','bindings'),('mdm_access','authorization_rules'),('mdm_access','user_groups'),('mdm_commands','capabilities'),('mdm_commands','operations'),('mdm_access','devices'),('mdm_access','registrations'),('mdm_access','report_sources'),('mdm_access','collection_runs'),('mdm','inventory'),('mdm_software_composition','subjects'),('mdm_software_composition','targets'),('mdm_software_composition','projections'),('mdm_software_release','aggregates'))
 AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner IN(SELECT oid FROM reachable) OR NOT has_table_privilege(current_user,c.oid,'SELECT') OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND p.oid NOT IN ('mdm.record_asset_change(uuid,text,jsonb,text[])'::regprocedure,'mdm.lock_asset_watermark(uuid)'::regprocedure,'rss_audit.reserve(uuid)'::regprocedure,'rss_audit.append(uuid,text,text,bigint,bytea,bigint)'::regprocedure,'rss_ledger.prepare_append(uuid,text,text,smallint)'::regprocedure,'rss_ledger.insert_entry(uuid,text,text,bigint,bytea,bytea,bytea,text,smallint)'::regprocedure,'mdm_planning.scope_admission(uuid,text)'::regprocedure,'mdm_planning.policy_lock(uuid)'::regprocedure,'mdm_content.reference_ready()'::regprocedure,'rss_reconcile.assert_tenant(uuid)'::regprocedure,'rss_reconcile.wake(uuid,text,text)'::regprocedure,'rss_reconcile.claim_due(uuid,text,integer,bigint)'::regprocedure,'rss_reconcile.lock_claim(uuid,text,text,uuid,bigint)'::regprocedure,'rss_reconcile.renew(uuid,text,text,uuid,bigint,bigint)'::regprocedure,'rss_reconcile.finish(uuid,text,text,uuid,bigint,bigint,text,bigint,bigint)'::regprocedure,'rss_reconcile.release(uuid,text,text,uuid,bigint)'::regprocedure,'rss_reconcile.mark_applied(uuid,text,text,uuid,bigint)'::regprocedure,'rss_transactional_messaging.check_execution()'::regprocedure,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)'::regprocedure,'rss_transactional_messaging.append_outbox(bytea,jsonb)'::regprocedure) AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg_%' AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM tables t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute c ON c.attrelid=t.oid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))

 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm.manual_assignments'::regclass AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)

 AND (SELECT jsonb_agg(jsonb_build_array(attname,format_type(atttypid,atttypmod),attnotnull) ORDER BY attnum)
 FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped)='[["tenant_id","uuid",true],["device","text",true],["field","text",true],["revision","bigint",true],["fact","jsonb",true]]'::jsonb
 AND (SELECT count(*)=3 AND bool_and(convalidated AND pg_get_constraintdef(oid)=CASE conname
 WHEN 'manual_assignments_field_check' THEN 'CHECK (((length(field) <= 128) AND (field ~ ''^custom\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$''::text)))'
 WHEN 'manual_assignments_revision_check' THEN 'CHECK ((revision > 0))'
 WHEN 'manual_assignments_fact_check' THEN 'CHECK ((octet_length((fact)::text) <= 16777216))' ELSE '' END)
 FROM pg_constraint WHERE conrelid=c.oid AND contype='c')
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND has_column_privilege(current_user,c.oid,'revision','UPDATE') AND has_column_privilege(current_user,c.oid,'fact','UPDATE')
 AND (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)=1
 AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=c.oid AND contype='p' AND convalidated AND pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, device, field)')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND (has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(a.attname IN('revision','fact')) OR has_column_privilege(current_user,c.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c,LATERAL aclexplode(c.attacl) a WHERE c.attrelid='mdm.manual_assignments'::regclass AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 )

 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_access.credentials'::regclass
 AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','registration','state'))))

 AND has_function_privilege(current_user,'mdm_planning.scope_admission(uuid,text)','EXECUTE')

 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_apple.devices'::regclass
 AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','registration','state','access_rights'))))
 -- Apple collection reads are exact metadata capabilities, never native secrets.
 AND NOT EXISTS(
 SELECT 1 FROM (VALUES
 ('mdm_apple.channels',ARRAY['tenant_id','registration','generation','user_key','state'])
 ) expected(relation,columns)
 JOIN pg_class c ON c.oid=expected.relation::regclass
 WHERE NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner IN(SELECT oid FROM reachable)
 OR NOT has_schema_privilege(current_user,c.relnamespace,'USAGE')
 OR has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT')<>(a.attname=ANY(expected.columns))))
 -- Fixed installer publication authority belongs to the same software runtime.
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_agent_packages.releases'::regclass
 AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
 AND c.relowner NOT IN(SELECT oid FROM package_reachable)
 AND has_schema_privilege(current_user,c.relnamespace,'USAGE')
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT EXISTS(SELECT 1 FROM package_reachable r WHERE has_schema_privilege(r.oid,c.relnamespace,'CREATE')
 OR has_table_privilege(r.oid,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 AND (SELECT jsonb_agg(jsonb_build_array(attname,format_type(atttypid,atttypmod),attnotnull) ORDER BY attnum)
 FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped)='[["tenant_id","uuid",true],["id","uuid",true],["operation_id","uuid",true],["request_digest","bytea",true],["document","jsonb",true],["binding","jsonb",true],["state","text",true]]'::jsonb
 AND (SELECT count(*)=6 AND bool_and(convalidated AND pg_get_constraintdef(oid)=CASE conname
 WHEN 'releases_binding_check' THEN 'CHECK ((octet_length((binding)::text) <= 32768))'
 WHEN 'releases_document_check' THEN 'CHECK ((octet_length((document)::text) <= 32768))'
 WHEN 'releases_request_digest_check' THEN 'CHECK ((octet_length(request_digest) = 32))'
 WHEN 'releases_state_check' THEN 'CHECK ((state = ANY (ARRAY[''published''::text, ''withdrawn''::text])))'
 WHEN 'releases_pkey' THEN 'PRIMARY KEY (tenant_id, id)'
 WHEN 'releases_tenant_id_operation_id_key' THEN 'UNIQUE (tenant_id, operation_id)' ELSE '' END)
 FROM pg_constraint WHERE conrelid=c.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid=c.oid AND (NOT indisvalid OR NOT indisready OR NOT indislive))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(a.attname='state')
 OR EXISTS(SELECT 1 FROM package_reachable r WHERE has_column_privilege(r.oid,c.oid,a.attnum,'REFERENCES')
 OR (has_column_privilege(r.oid,c.oid,a.attnum,'UPDATE') AND a.attname<>'state'))))
 AND (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)=1
 AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM package_reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute col,LATERAL aclexplode(col.attacl) a WHERE col.attrelid=c.oid AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM package_reachable) AND a.is_grantable))))

 -- Installation purpose is global immutable metadata, never a tenant business capability.
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='public.mdm_installation'::regclass
 AND c.relkind='r' AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND has_schema_privilege(current_user,c.relnamespace,'USAGE')
 AND NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT')<>(a.attname IN('instance_id','management_tenant_id')))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute col,LATERAL aclexplode(col.attacl) a WHERE col.attrelid=c.oid
 AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))))
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_devices.input_snapshots'::regclass AND c.relrowsecurity AND c.relforcerowsecurity AND has_table_privilege(current_user,c.oid,'SELECT,INSERT') AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_devices.input_objects'::regclass AND c.relrowsecurity AND c.relforcerowsecurity AND has_table_privilege(current_user,c.oid,'SELECT,INSERT') AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))

 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='mdm_devices.input_snapshots'::regclass AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE')<>(a.attname IN('phase','cursor','object_count','byte_count')))
 AND NOT has_any_column_privilege(current_user,'mdm_devices.input_objects','UPDATE,REFERENCES')
;
