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
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['asset_dispatch','asset_query_facets','asset_query_results','asset_query_runs','automation_jobs','configuration_claims','configuration_devices','configuration_objects','cursor_keys','event_batches','event_members','field_layouts','group_definition_walk','group_fields','group_operations','group_selections','native_protection','operations','operations','operations','operations','policy_assignments','saved_queries','scope_channel_results','scope_results','scope_runs','scope_source_members','scope_sources','scope_versions','scopes','source_heads'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
 OR oid IN(SELECT relowner FROM tables))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR has_table_privilege(current_user,t.oid,'INSERT')<>(t.relname NOT IN('configuration_claims','configuration_objects'))
 OR has_table_privilege(current_user,t.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_table_privilege(current_user,t.oid,'DELETE')<>(t.relname IN('group_fields','scope_sources','group_definition_walk'))
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <> ((t.relname='group_definition_walk' AND a.attname IN('graph_revision','visited')) OR (t.relname='source_heads' AND a.attname IN('revision','required_input','observed_input')) OR (t.relname='scopes' AND a.attname IN('revision','deleted','resolution','resolution_revision','calculation_revision','agent_resolution_revision','mdm_resolution_revision')) OR (t.relname IN('saved_queries','field_layouts') AND a.attname IN('revision','document')) OR (t.relname='automation_jobs' AND a.attname IN('forwarded','completed','failure','failure_detail','cursor','authority_revision','replacement_task')) OR (t.relname='asset_query_runs' AND a.attname IN('total','matched','unknown')) OR (t.relname='asset_query_facets' AND a.attname='total') OR (t.relname='asset_dispatch' AND a.attname IN('consumed','watermark','cursor','phase','failure','failure_generation','relation_revision','relation_cursor','relation_pending_revision')) OR (t.relname='scope_runs' AND a.attname IN('phase','source_index','source_cursor','evaluation_cursor','projection_cursor','channel_hashes','object_count','member_count','identity_revision','result_fingerprint','previous_resolution','semantic_changed')) OR (t.relname='scope_channel_results' AND a.attname IN('matched','pending','target','entry_revision')) OR (t.relname='configuration_devices' AND a.attname='input_revision') OR (t.relname='policy_assignments' AND a.attname IN('input','availability','reason','target','scope_result','entry_revision'))) OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(current_user,n.oid,'CREATE'))
 AND has_schema_privilege(current_user,'mdm_planning','USAGE')
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN('r','v','m','f')
 AND n.nspname NOT IN('mdm_planning','mdm_flow','mdm_assets','mdm_automation','mdm_resource_catalog','mdm_publication','mdm_software','mdm_content','mdm_content_connections','mdm_group','mdm_policy','mdm_resource','mdm_compliance','mdm_telemetry')
 AND (n.nspname,c.relname) NOT IN(('mdm_devices','retirement_policies'),('mdm_devices','retirements'),('mdm_devices','retirement_channels'),('mdm_devices','retirement_work'),('mdm_devices','associations'),('mdm_devices','members'),('mdm_devices','checkpoints'),('mdm_devices','input_snapshots'),('mdm_devices','input_objects'),('mdm_access','agent_configuration_keys'),('public','mdm_installation'),('mdm_agent_packages','releases'),('mdm_apple','devices'),('mdm_apple','channels'),('mdm_agent','bindings'),('mdm_task_signing','heads'),('mdm_task_signing','versions'),('mdm_task_signing','acknowledgements'),('mdm_access','agent_connection_versions'),('mdm_access','authorization_rules'),('mdm_access','user_groups'),('mdm_access','api_keys'),('mdm_commands','capabilities'),('mdm_commands','operations'),('mdm_commands','action_polls'),('mdm','field_versions'),('mdm','retention_policies'),('mdm','collection_definitions'),('mdm','collection_results'),('mdm','asset_clock'),('mdm','asset_changes'),('mdm','inventory_history'),('mdm','manual_history'),('mdm_access','asset_authority_history'),('mdm_access','collection_history'),('rss_reconcile','targets'),('rss_audit','records'),('rss_ledger','heads'),('rss_ledger','entries'),('mdm_access','devices'),('mdm_access','registrations'),('mdm_access','report_sources'),('mdm_access','collection_runs'),('mdm','inventory'),('mdm','array_versions'),('mdm','array_items'),('mdm_access','collection_versions'),('mdm_access','collection_items'),('mdm','manual_assignments'),('mdm_access','credentials'),('mdm_access','agent_issuances'),('mdm_webhook','subscriptions'),('mdm_webhook','versions'),('mdm_webhook','events'),('mdm_webhook','compliance_sources'),('mdm_webhook','fanout'),('mdm_webhook','deliveries'),('mdm_webhook','operations'),('mdm_software_composition','withdrawals'),('mdm_software_composition','subjects'),('mdm_software_composition','targets'),('mdm_software_composition','projections'),('mdm_software_release','aggregates'),('rss_transactional_messaging','policy'),('rss_transactional_messaging','outbox'))
 AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname,c.relname) IN(('mdm_devices','associations'),('mdm_devices','members'),('mdm_devices','checkpoints'),('mdm_agent','bindings'),('mdm_task_signing','heads'),('mdm_task_signing','versions'),('mdm_task_signing','acknowledgements'),('mdm_access','agent_connection_versions'),('mdm_access','authorization_rules'),('mdm_access','user_groups'),('mdm_access','api_keys'),('mdm_commands','capabilities'),('mdm_commands','operations'),('mdm_access','registrations'),('mdm_access','report_sources'),('mdm','inventory'),('mdm_access','collection_versions'),('mdm_access','collection_items'),('mdm_software_composition','subjects'),('mdm_software_composition','targets'),('mdm_software_composition','projections'),('mdm_software_release','aggregates'))
 AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner IN(SELECT oid FROM reachable) OR NOT has_table_privilege(current_user,c.oid,'SELECT') OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM (VALUES
 ('mdm_webhook.subscriptions',ARRAY['revision','target_version','enabled','deleted','settings']::text[]),
 ('mdm_webhook.versions',ARRAY['retired']::text[]),
 ('mdm_webhook.events',ARRAY[]::text[]),
 ('mdm_webhook.compliance_sources',ARRAY['cursor','complete']::text[]),
 ('mdm_webhook.fanout',ARRAY['cursor','complete']::text[]),
 ('mdm_webhook.deliveries',ARRAY['attempts','last_outcome','last_stage','last_reason']::text[]),
 ('mdm_webhook.operations',ARRAY[]::text[])
 ) expected(relation,updates) JOIN pg_class c ON c.oid=expected.relation::regclass
 WHERE NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner IN(SELECT oid FROM reachable)
 OR NOT has_table_privilege(current_user,c.oid,'SELECT') OR NOT has_table_privilege(current_user,c.oid,'INSERT')
 OR has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(current_user,c.oid,'REFERENCES')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(a.attname=ANY(expected.updates))))
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_software_composition.withdrawals'::regclass
 AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,c.oid,'UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname NOT IN ('information_schema','rss_audit','rss_ledger') AND p.oid NOT IN ('mdm_access.operation_authority_valid(jsonb,text,bigint)'::regprocedure,'mdm_access.operation_authority_valid_until(jsonb,text,bigint)'::regprocedure,'mdm_access.access_binding_ready(jsonb)'::regprocedure,'mdm_devices.object_current(jsonb,text)'::regprocedure,'mdm_devices.lock_query_revision(uuid)'::regprocedure,'mdm_planning.scope_state(uuid,text)'::regprocedure,'mdm_planning.channel_admission(uuid,text,text)'::regprocedure,'mdm_commands.access_policy(uuid,text,bigint)'::regprocedure,'mdm_commands.active_access_binding(uuid,bigint,bigint)'::regprocedure,'mdm.append_field_version(uuid,text,bigint,jsonb)'::regprocedure,'mdm.record_asset_change(uuid,text,jsonb,text[])'::regprocedure,'mdm.lock_asset_watermark(uuid)'::regprocedure,'mdm_planning.scope_admission(uuid,text)'::regprocedure,'mdm_planning.group_current(uuid)'::regprocedure,'mdm_planning.policy_lock(uuid)'::regprocedure,'mdm_content.reference_ready()'::regprocedure,'rss_reconcile.assert_tenant(uuid)'::regprocedure,'rss_reconcile.wake(uuid,text,text)'::regprocedure,'rss_reconcile.claim_due(uuid,text,integer,bigint)'::regprocedure,'rss_reconcile.lock_claim(uuid,text,text,uuid,bigint)'::regprocedure,'rss_reconcile.renew(uuid,text,text,uuid,bigint,bigint)'::regprocedure,'rss_reconcile.finish(uuid,text,text,uuid,bigint,bigint,text,bigint,bigint)'::regprocedure,'rss_reconcile.release(uuid,text,text,uuid,bigint)'::regprocedure,'rss_reconcile.mark_applied(uuid,text,text,uuid,bigint)'::regprocedure,'rss_transactional_messaging.check_execution()'::regprocedure,'rss_transactional_messaging.consumer_scope_domain()'::regprocedure,'rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text)'::regprocedure,'rss_transactional_messaging.projection_scope_matches(text,text)'::regprocedure,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)'::regprocedure,'rss_transactional_messaging.append_outbox(bytea,jsonb)'::regprocedure) AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg_%' AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM tables t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute c ON c.attrelid=t.oid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))

 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm.manual_assignments'::regclass AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)

 AND (SELECT jsonb_agg(jsonb_build_array(attname,format_type(atttypid,atttypmod),attnotnull) ORDER BY attnum)
 FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped)='[["tenant_id","uuid",true],["device","text",true],["field","text",true],["revision","bigint",true],["fact","jsonb",true],["value_version","text",false],["last_known_version","text",false]]'::jsonb
 AND (SELECT count(*)=4 AND bool_and(convalidated AND pg_get_constraintdef(oid)=CASE conname
 WHEN 'manual_assignments_field_check' THEN 'CHECK (((length(field) <= 128) AND (field ~ ''^(device|custom|channel)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$''::text)))'
 WHEN 'manual_assignments_revision_check' THEN 'CHECK ((revision > 0))'
 WHEN 'manual_value_representation' THEN 'CHECK (((((fact #>> ''{state,kind}''::text[]) = ''known''::text) = (((fact #> ''{state,value}''::text[]) IS NOT NULL) OR (value_version IS NOT NULL))) AND (NOT (((fact #> ''{state,value}''::text[]) IS NOT NULL) AND (value_version IS NOT NULL))) AND ((value_version IS NULL) OR ((fact #>> ''{state,kind}''::text[]) = ''known''::text)) AND ((last_known_version IS NULL) OR (((fact #> ''{lastKnown,evidence}''::text[]) IS NOT NULL) AND ((fact #> ''{lastKnown,value}''::text[]) IS NULL))) AND ((fact #>> ''{state,value,kind}''::text[]) IS DISTINCT FROM ''array''::text) AND ((fact #>> ''{lastKnown,value,kind}''::text[]) IS DISTINCT FROM ''array''::text)))'
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
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND (has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(a.attname IN('revision','fact','value_version','last_known_version')) OR has_column_privilege(current_user,c.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c,LATERAL aclexplode(c.attacl) a WHERE c.attrelid='mdm.manual_assignments'::regclass AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 )

 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_access.credentials'::regclass
 AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','id','registration','state'))))

 AND has_function_privilege(current_user,'mdm_planning.scope_admission(uuid,text)','EXECUTE')
 AND has_function_privilege(current_user,'mdm_planning.group_current(uuid)','EXECUTE')

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
 FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped)='[["tenant_id","uuid",true],["id","uuid",true],["document","jsonb",true],["binding","jsonb",true],["state","text",true],["platform","text",true],["architecture","text",true],["format","text",true],["product_version","text",true]]'::jsonb
 AND (SELECT count(*)=5 AND bool_and(convalidated AND pg_get_constraintdef(oid)=CASE conname
 WHEN 'releases_business_key' THEN 'UNIQUE (tenant_id, platform, architecture, format, product_version)'
 WHEN 'releases_binding_check' THEN 'CHECK ((octet_length((binding)::text) <= 32768))'
 WHEN 'releases_document_check' THEN 'CHECK ((octet_length((document)::text) <= 32768))'
 WHEN 'releases_state_check' THEN 'CHECK ((state = ANY (ARRAY[''published''::text, ''withdrawn''::text])))'
 WHEN 'releases_pkey' THEN 'PRIMARY KEY (tenant_id, id)' ELSE '' END)
 FROM pg_constraint WHERE conrelid=c.oid)
 AND (SELECT count(*)=4 AND bool_and(a.attgenerated='s' AND regexp_replace(pg_get_expr(d.adbin,d.adrelid),'[[:space:]()]','','g')=CASE a.attname
 WHEN 'platform' THEN 'document#>>''{target,platform}''::text[]'
 WHEN 'architecture' THEN 'document#>>''{target,architecture}''::text[]'
 WHEN 'format' THEN 'document->>''format''::text'
 WHEN 'product_version' THEN 'document->>''version''::text' ELSE '' END)
 FROM pg_attribute a JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum)
 WHERE a.attrelid=c.oid AND a.attname IN('platform','architecture','format','product_version'))
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
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE (n.nspname,c.relname) IN(('mdm_access','devices'),('mdm_devices','retirement_policies'),('mdm_devices','retirements'),('mdm_devices','retirement_channels'),('mdm_devices','retirement_work'))
 AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner IN(SELECT oid FROM reachable)
 OR NOT has_table_privilege(current_user,c.oid,'SELECT')
 OR has_table_privilege(current_user,c.oid,'INSERT')<>(c.relname IN('retirements','retirement_channels','retirement_policies'))
 OR has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>((c.relname='devices' AND a.attname='retirement') OR (c.relname='retirement_channels' AND a.attname IN('stage','effect','execution','blocking_execution','reason')))
 OR has_column_privilege(current_user,c.oid,a.attnum,'REFERENCES')))))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_content_connections' AND c.relkind='r' AND (has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND (SELECT count(*)=2 AND bool_and(c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
 AND c.relowner='mdm_owner'::regrole AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND has_schema_privilege(current_user,c.relnamespace,'USAGE') AND has_table_privilege(current_user,c.oid,'SELECT')
 AND (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)=1
 AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_content_connections' AND c.relname IN('heads','versions'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_content_connections' AND c.relname NOT IN('heads','versions')
 AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT has_function_privilege(current_user,'mdm_content_connections.reserve(bigint,uuid,text,boolean,bytea,text,bytea,bigint)','EXECUTE')

 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_access.collection_runs'::regclass
 AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE has_table_privilege(r.oid,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'UPDATE,REFERENCES')))
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='mdm_access.agent_configuration_keys'::regclass
 AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','public_key'))));
