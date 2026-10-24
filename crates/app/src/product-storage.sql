-- Version-bound dependency contract from the installed migrations. OIDs and role
-- numbers are rendered as names; values/data are never included in this snapshot.
-- Audit worker Ledger grants vary by installed mode; each worker verifies its
-- profile at installation and startup. Other ACLs stay exact.
-- Canonical constraint output removes redundant AND grouping introduced by
-- BETWEEN expansion, so a logical pg_dump/pg_restore preserves the contract.
-- Pretty rule deparsing normalizes redundant AND groups expanded from row comparisons
-- before pg_dump; equivalent restored views retain the same complete definition.
-- Foreign-key targets are always schema qualified, independent of the caller search_path.
WITH relations AS (
 SELECT c.*,n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE c.relkind IN('r','v') AND ((n.nspname='mdm_pki' AND c.relname IN('trust','rotations','installations','acknowledgements','certificates','revocations')) OR (n.nspname='mdm_agent_packages' AND c.relname='releases') OR (n.nspname='mdm_content' AND c.relname='manifests') OR (n.nspname='mdm_flow' AND c.relname='native_protection') OR (n.nspname='mdm' AND c.relname IN('inventory','array_versions','array_items')) OR n.nspname IN('mdm_recovery','mdm_windows','mdm_agent','rss_device_command','rss_reconcile','mdm_apple','rss_audit','rss_ledger','mdm_audit','mdm_planning','mdm_policy','mdm_software','mdm_devices') OR (n.nspname='mdm_resource' AND c.relname IN ('aggregates','immutable')) OR (n.nspname='mdm_access' AND c.relname IN
 ('device_access_bindings','device_access_results','agent_bootstraps','agent_native_enrollments','agent_enrollment_settings','agent_connection_versions','agent_configuration_keys','agent_grants','agent_issuances','requests','devices','registrations','credentials','report_sources','enrollment_intents','enrollment_certificates','authorization_rules','user_groups','api_keys','management_sessions','management_messages','collection_runs','collection_versions','collection_items')))
), contracts AS (
 SELECT t.nspname||'.'||t.relname AS name, encode(sha256(convert_to(jsonb_build_object(
 'shape',jsonb_build_array(t.relkind,t.relpersistence,t.relrowsecurity,t.relforcerowsecurity,pg_get_userbyid(t.relowner)),
 'columns',(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated) ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(c.conname,CASE WHEN c.contype='f' THEN replace(pg_get_constraintdef(c.oid,true),'REFERENCES '||c.confrelid::regclass::text,'REFERENCES '||(SELECT format('%I.%I',n.nspname,r.relname) FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace WHERE r.oid=c.confrelid)) ELSE pg_get_constraintdef(c.oid,true) END,c.convalidated) ORDER BY c.conname COLLATE "C") FROM pg_constraint c WHERE c.conrelid=t.oid),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive) ORDER BY pg_get_indexdef(i.indexrelid) COLLATE "C") FROM pg_index i WHERE i.indrelid=t.oid),
 'policies',(SELECT jsonb_agg(jsonb_build_array(p.polname,p.polcmd,p.polpermissive,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid),(SELECT array_agg(CASE WHEN r=0 THEN 'PUBLIC' ELSE pg_get_userbyid(r)::text END ORDER BY r) FROM unnest(p.polroles) r)) ORDER BY p.polname COLLATE "C") FROM pg_policy p WHERE p.polrelid=t.oid),
 'triggers',(SELECT jsonb_agg(pg_get_triggerdef(tg.oid) ORDER BY tg.tgname COLLATE "C") FROM pg_trigger tg WHERE tg.tgrelid=t.oid AND NOT tg.tgisinternal),
 'rewrite',(SELECT jsonb_agg(pg_get_ruledef(r.oid,true) ORDER BY r.rulename COLLATE "C") FROM pg_rewrite r WHERE r.ev_class=t.oid)
 )::text,'UTF8')),'hex') AS digest FROM relations t
 UNION ALL
 SELECT n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',
 encode(sha256(convert_to(jsonb_build_object('definition',pg_get_functiondef(p.oid),'owner',pg_get_userbyid(p.proowner),
 'acl',(SELECT jsonb_agg(jsonb_build_array(CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END,a.privilege_type,a.is_grantable) ORDER BY CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END COLLATE "C",a.privilege_type,a.is_grantable) FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE NOT (n.nspname='rss_ledger' AND pg_get_userbyid(a.grantee) IN ('mdm_identity_audit','mdm_audit_worker'))))::text,'UTF8')),'hex')
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname IN('mdm_windows','mdm_agent','mdm_devices','mdm_apple','rss_device_command','rss_reconcile','rss_audit','rss_ledger') OR (n.nspname,p.proname) IN (('mdm_access','operation_authority_valid'),('mdm_access','operation_authority_valid_until'),('mdm_access','access_binding_ready'),('mdm_devices','object_current'),('mdm_planning','scope_state'),('mdm_planning','channel_admission'),('mdm_commands','access_policy'),('mdm_commands','active_access_binding'),('mdm_apple','application_valid_until'),('mdm_apple','platform_session_qualifications'),('mdm','lock_asset_watermark'),('mdm_access','capture_collection_metadata'),('mdm_access','capture_collection_history'),('mdm_access','immutable_collection'),('mdm_apple','account_current'),('mdm_planning','scope_admission'),('mdm_planning','policy_lock'))
)
SELECT jsonb_object_agg(name,digest)::text FROM contracts
