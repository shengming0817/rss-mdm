WITH allowed(schema_name,table_name) AS (VALUES
 ('mdm_recovery','entries'),('mdm_recovery','versions'),('mdm_recovery','disclosures'),('mdm_enterprise','brokers'),('mdm_enterprise','windows_sources'),('mdm_enterprise','subject_owners'),('mdm_enterprise','subject_versions'),('mdm_enterprise','subjects'),('mdm_enterprise','relying_parties'),('mdm_access','device_access_lifecycles'),('mdm_access','device_access_subject_denials'),('mdm_webhook','events'),('mdm_access','agent_issuances'),('mdm_agent','bindings'),('mdm_access','device_access_ceremonies'),('mdm_access','registration_operations'),('mdm_access','devices'),('mdm_access','registrations'),('mdm_access','credentials'),('mdm_access','report_sources'),('mdm_access','device_access_bindings'),
 ('mdm_access','authorization_rules'),('mdm_access','user_groups'),('mdm_access','authorization_initializations'),('mdm_access','api_keys'),
 ('mdm_policy','policies'),('mdm_policy','versions'),
 ('mdm_scope','scopes'),('mdm_scope','scope_runs'),('mdm_scope','scope_source_members'),('mdm_commands','scope_channel_results'),
 ('mdm_devices','associations'),('mdm_devices','members'),('mdm_devices','asset_states'),('mdm','asset_clock'),
 ('mdm_devices','input_snapshots'),('mdm_devices','input_objects'),('mdm_devices','checkpoints'),
 ('mdm_apple','psso_password_providers'),('mdm_apple','devices'),('mdm_apple','profiles'),('mdm_apple','attempts'),('mdm_apple','psso_sources'),('mdm_apple','psso_tokens'),
 ('mdm','inventory'),('mdm','collection_definitions')
), tables AS (
 SELECT cl.oid,n.nspname,cl.relname,cl.relrowsecurity,cl.relforcerowsecurity
 FROM pg_class cl JOIN pg_namespace n ON n.oid=cl.relnamespace
 WHERE n.nspname IN('mdm_access','mdm_policy','mdm_planning','mdm_scope','mdm_commands','mdm_devices','mdm_apple','mdm_agent','mdm_webhook','mdm_enterprise','mdm_recovery','mdm') AND cl.relkind='r'
), reachable AS (SELECT oid,rolsuper,rolbypassrls,rolcreaterole FROM pg_roles WHERE pg_has_role(current_user,oid,'SET'))
SELECT
 NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole)
 AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN pg_namespace n WHERE n.nspname IN('mdm_access','mdm_policy','mdm_planning','mdm_scope','mdm_commands','mdm_devices','mdm_apple','mdm_agent','mdm_webhook','mdm_enterprise','mdm_recovery','mdm') AND has_schema_privilege(r.oid,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT FROM allowed x WHERE NOT EXISTS(SELECT FROM tables t WHERE (t.nspname,t.relname)=(x.schema_name,x.table_name) AND t.relrowsecurity AND t.relforcerowsecurity AND has_table_privilege(current_user,t.oid,'SELECT')))
 AND NOT EXISTS(SELECT FROM reachable r CROSS JOIN tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped AND (
 (has_column_privilege(r.oid,t.oid,a.attnum,'SELECT') AND NOT EXISTS(SELECT FROM allowed x WHERE (t.nspname,t.relname)=(x.schema_name,x.table_name)))
 OR (has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE') AND NOT(
   (a.attname='tenant_id' AND (t.nspname,t.relname) IN (('mdm_recovery','entries'),('mdm_recovery','versions'),('mdm_apple','psso_sources'),('mdm_access','device_access_bindings')))
   OR ((t.nspname,t.relname)=('mdm_enterprise','brokers') AND a.attname IN ('document','sealed','expires_at','phase'))
   OR ((t.nspname,t.relname)=('mdm_enterprise','windows_sources') AND a.attname IN ('version','document'))
   OR (t.nspname='mdm_enterprise' AND t.relname IN ('subjects','relying_parties') AND a.attname IN ('revision','document'))
   OR ((t.nspname,t.relname)=('mdm_access','device_access_lifecycles') AND a.attname='document')
   OR ((t.nspname,t.relname)=('mdm_access','device_access_subject_denials') AND a.attname IN ('operation','denied'))
   OR ((t.nspname,t.relname)=('mdm_access','device_access_ceremonies') AND a.attname='consumed')
   OR ((t.nspname,t.relname)=('mdm_access','device_access_bindings') AND a.attname IN ('instance','principal','generation','revision','state','account','document'))))
 OR (has_column_privilege(r.oid,t.oid,a.attnum,'INSERT') AND (t.nspname,t.relname) NOT IN (('mdm_recovery','disclosures'),('mdm_enterprise','brokers'),('mdm_enterprise','windows_sources'),('mdm_enterprise','subject_owners'),('mdm_enterprise','subject_versions'),('mdm_enterprise','subjects'),('mdm_enterprise','relying_parties'),('mdm_access','device_access_lifecycles'),('mdm_access','device_access_subject_denials'),('mdm_webhook','events'),('mdm_access','device_access_ceremonies'),('mdm_access','device_access_bindings'),('mdm_access','registration_operations')))
 OR has_column_privilege(r.oid,t.oid,a.attnum,'REFERENCES') OR has_table_privilege(r.oid,t.oid,'TRUNCATE,TRIGGER') OR (has_table_privilege(r.oid,t.oid,'DELETE') AND (t.nspname,t.relname)<>('mdm_access','device_access_ceremonies'))))
 AND has_column_privilege(current_user,'mdm_apple.psso_sources','tenant_id','UPDATE')
 AND has_column_privilege(current_user,'mdm_access.device_access_bindings','tenant_id','UPDATE')
 AND has_function_privilege(current_user,'mdm.lock_asset_watermark(uuid)','EXECUTE')
 AND has_function_privilege(current_user,'mdm_policy.lock_policy(uuid)','EXECUTE')
 AND has_function_privilege(current_user,'mdm_scope.scope_admission(uuid,text)','EXECUTE')

 AND has_function_privilege(current_user,'mdm_apple.profile_qualifications(uuid[])','EXECUTE')
 AND has_function_privilege(current_user,'mdm_apple.platform_session_qualifications(uuid,jsonb,bigint)','EXECUTE')
 AND has_function_privilege(current_user,'mdm_commands.active_access_binding(uuid,bigint,bigint)','EXECUTE')

 AND has_table_privilege(current_user,'mdm_access.registration_operations','SELECT,INSERT')
 AND has_table_privilege(current_user,'mdm_access.device_access_bindings','INSERT')
 AND NOT EXISTS(SELECT FROM unnest(ARRAY['instance','principal','generation','revision','state','account','document']) AS col
 WHERE NOT has_column_privilege(current_user,'mdm_access.device_access_bindings',col,'UPDATE'))
