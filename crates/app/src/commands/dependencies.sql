-- Version-bound dependency contract from the installed migrations. OIDs and role
-- numbers are rendered as names; values/data are never included in this snapshot.
WITH relations AS (
 SELECT c.*,n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE c.relkind='r' AND (n.nspname IN('rss_device_command','rss_reconcile','mdm_apple') OR (n.nspname='mdm_resource' AND c.relname IN ('aggregates','immutable')) OR (n.nspname='mdm_access' AND c.relname IN
 ('requests','agent_bindings','devices','registrations','credentials','report_sources','enrollment_intents','enrollment_certificates','authorization_rules','user_groups','management_sessions','management_messages','collection_runs','audit')))
), contracts AS (
 SELECT t.nspname||'.'||t.relname AS name, encode(sha256(convert_to(jsonb_build_object(
 'shape',jsonb_build_array(t.relkind,t.relpersistence,t.relrowsecurity,t.relforcerowsecurity,pg_get_userbyid(t.relowner)),
 'columns',(SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated) ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(c.conname,pg_get_constraintdef(c.oid),c.convalidated) ORDER BY c.conname COLLATE "C") FROM pg_constraint c WHERE c.conrelid=t.oid),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive) ORDER BY pg_get_indexdef(i.indexrelid) COLLATE "C") FROM pg_index i WHERE i.indrelid=t.oid),
 'policies',(SELECT jsonb_agg(jsonb_build_array(p.polname,p.polcmd,p.polpermissive,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid),(SELECT array_agg(CASE WHEN r=0 THEN 'PUBLIC' ELSE pg_get_userbyid(r)::text END ORDER BY r) FROM unnest(p.polroles) r)) ORDER BY p.polname COLLATE "C") FROM pg_policy p WHERE p.polrelid=t.oid),
 'triggers',(SELECT jsonb_agg(pg_get_triggerdef(tg.oid) ORDER BY tg.tgname COLLATE "C") FROM pg_trigger tg WHERE tg.tgrelid=t.oid AND NOT tg.tgisinternal),
 'rewrite',(SELECT jsonb_agg(pg_get_ruledef(r.oid) ORDER BY r.rulename COLLATE "C") FROM pg_rewrite r WHERE r.ev_class=t.oid)
 )::text,'UTF8')),'hex') AS digest FROM relations t
 UNION ALL
 SELECT n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',
 encode(sha256(convert_to(jsonb_build_object('definition',pg_get_functiondef(p.oid),'owner',pg_get_userbyid(p.proowner),
 'acl',(SELECT jsonb_agg(jsonb_build_array(CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END,a.privilege_type,a.is_grantable) ORDER BY CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END COLLATE "C",a.privilege_type,a.is_grantable) FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a))::text,'UTF8')),'hex')
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname IN('rss_device_command','rss_reconcile') OR (n.nspname,p.proname) IN (('mdm_management','plan_execution_admission'),('mdm_policy_projection','execution_admission'))
)
SELECT jsonb_object_agg(name,digest)::text FROM contracts
