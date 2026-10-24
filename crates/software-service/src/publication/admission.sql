WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_software_composition' AND c.relkind='r'
), reachable AS (
 SELECT * FROM pg_roles WHERE oid=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 OR pg_has_role(current_user,oid,'MEMBER')
)
SELECT
 (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['authorities','bindings','projections','slots','subjects','targets','withdrawals'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_software_composition' AND c.relkind NOT IN('r','i'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='mdm_software_composition')
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
 OR oid IN (SELECT relowner FROM tables) OR has_schema_privilege(oid,'mdm_software_composition','CREATE'))
 AND has_schema_privilege(current_user,'mdm_software_composition','USAGE')
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT t.relrowsecurity OR NOT t.relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT')
 OR NOT has_table_privilege(current_user,t.oid,'INSERT')
 OR has_table_privilege(current_user,t.oid,'TRUNCATE,REFERENCES,TRIGGER,UPDATE')
 OR has_table_privilege(current_user,t.oid,'DELETE')<>(t.relname='projections')
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'))
 AND NOT EXISTS(SELECT 1 FROM tables t, LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n,LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
 WHERE n.nspname='mdm_software_composition' AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <>
  (t.relname='authorities' AND a.attname='record' OR t.relname='slots' AND a.attname IN('operation','cursor') OR t.relname='targets' AND a.attname IN('attempted','acknowledged','call_generation') OR t.relname='withdrawals' AND a.attname='complete' OR t.relname='projections' AND a.attname='publication')
 OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid,
 LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=0
 OR (acl.grantee IN(SELECT oid FROM reachable) AND acl.is_grantable))

 AND has_schema_privilege(current_user,'mdm_audit','USAGE')
 AND has_table_privilege(current_user,'mdm_audit.receipts','SELECT,INSERT')
 AND NOT has_table_privilege(current_user,'mdm_audit.receipts','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND (SELECT relrowsecurity AND relforcerowsecurity AND relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_class WHERE oid='mdm_audit.receipts'::regclass)
 -- Final composition admission closes permissions outside the three owned surfaces.
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
 AND c.relkind IN ('r','v','m','f')
 AND n.nspname NOT IN ('mdm_resource','mdm_software_release','mdm_software_composition')
 AND (n.nspname,c.relname) NOT IN (('rss_audit','heads'),('rss_audit','records'),('rss_ledger','heads'),('rss_ledger','entries'),('mdm_audit','receipts'),('mdm_audit','backlog'),('mdm_software','sources'),('mdm_software','versions'),('mdm_software','materials'),('mdm_access','authorization_rules'),('mdm_access','user_groups'),('mdm_access','api_keys'),('public','mdm_installation'),('mdm_content','manifests'),('rss_transactional_messaging','policy'),('rss_transactional_messaging','outbox'))
 AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE c.relkind='S' AND n.nspname NOT IN ('pg_catalog','information_schema')

 AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname NOT IN ('pg_catalog','information_schema')
 AND p.oid NOT IN ('mdm_access.operation_authority_valid(jsonb,text,bigint)'::regprocedure,'mdm_access.operation_authority_valid_until(jsonb,text,bigint)'::regprocedure,'mdm_content.reference_ready()'::regprocedure,'rss_transactional_messaging.check_execution()'::regprocedure,'rss_transactional_messaging.consumer_scope_domain()'::regprocedure,'rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text)'::regprocedure,'rss_transactional_messaging.projection_scope_matches(text,text)'::regprocedure,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)'::regprocedure,'rss_transactional_messaging.append_outbox(bytea,jsonb)'::regprocedure)
 AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND (SELECT count(*)=1 FROM pg_policy WHERE polrelid='mdm_audit.receipts'::regclass)
 AND EXISTS(SELECT 1 FROM pg_policy WHERE polrelid='mdm_audit.receipts'::regclass AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid')
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(current_user,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
 WHERE c.oid='mdm_audit.receipts'::regclass AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c,LATERAL aclexplode(c.attacl) a
 WHERE c.attrelid='mdm_audit.receipts'::regclass AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))

 AND has_schema_privilege(current_user,'mdm_software','USAGE')
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_software' AND c.relkind='r'
 AND (has_table_privilege(current_user,c.oid,'SELECT')<>(c.relname IN('sources','versions','materials'))
 OR has_table_privilege(current_user,c.oid,'INSERT')<>(c.relname IN('versions','materials'))
 OR has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(current_user,c.oid,'REFERENCES')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(c.relname='versions' AND a.attname='lifecycle'))
 OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner IN(SELECT oid FROM reachable)))

 -- Resource reference insertion executes the content deletion guard under this role.
 AND has_schema_privilege(current_user,'mdm_content','USAGE')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='mdm_content.manifests'::regclass AND a.attnum>0 AND NOT a.attisdropped
     AND has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','sha256','state')))
 AND NOT has_table_privilege(current_user,'mdm_content.manifests','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,'mdm_content.manifests','INSERT,UPDATE,REFERENCES')
 AND (SELECT relrowsecurity AND relforcerowsecurity AND relowner NOT IN(SELECT oid FROM reachable)
      FROM pg_class WHERE oid='mdm_content.manifests'::regclass)

 -- Publication can read current authorization, but cannot write rules or installation identity.
 AND NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid IN('mdm_access.authorization_rules'::regclass,'mdm_access.user_groups'::regclass,'mdm_access.api_keys'::regclass)
 AND (NOT has_table_privilege(current_user,c.oid,'SELECT') OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='public.mdm_installation'::regclass AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')<>(a.attname IN('instance_id','management_tenant_id')))
 AND NOT has_table_privilege(current_user,'public.mdm_installation','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,'public.mdm_installation','INSERT,UPDATE,REFERENCES')
