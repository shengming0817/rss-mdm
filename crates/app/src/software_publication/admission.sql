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
  (t.relname='authorities' AND a.attname='candidate' OR t.relname='slots' AND a.attname IN('operation','cursor') OR t.relname='targets' AND a.attname IN('attempted','acknowledged') OR t.relname='withdrawals' AND a.attname='complete' OR t.relname='projections' AND a.attname='publication')
 OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid,
 LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=0
 OR (acl.grantee IN(SELECT oid FROM reachable) AND acl.is_grantable))

 AND has_schema_privilege(current_user,'mdm_access','USAGE')
 AND has_table_privilege(current_user,'mdm_access.audit','INSERT')
 AND NOT has_table_privilege(current_user,'mdm_access.audit','SELECT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES')
 AND (SELECT relrowsecurity AND relforcerowsecurity AND relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_class WHERE oid='mdm_access.audit'::regclass)
 -- Final composition admission closes permissions outside the three owned surfaces.
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
 AND c.relkind IN ('r','v','m','f')
 AND n.nspname NOT IN ('mdm_resource','mdm_software_release','mdm_software_composition')
 AND (n.nspname,c.relname) NOT IN (('mdm_access','audit'),('rss_transactional_messaging','policy'),('rss_transactional_messaging','outbox'))
 AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE c.relkind='S' AND n.nspname NOT IN ('pg_catalog','information_schema')
 AND (n.nspname,c.relname)<>('rss_transactional_messaging','outbox_seq_seq')
 AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname NOT IN ('pg_catalog','information_schema')
 AND p.oid<>'rss_transactional_messaging.check_execution()'::regprocedure
 AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND (SELECT count(*)=1 FROM pg_policy WHERE polrelid='mdm_access.audit'::regclass)
 AND EXISTS(SELECT 1 FROM pg_policy WHERE polrelid='mdm_access.audit'::regclass AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid')
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(current_user,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
 WHERE c.oid='mdm_access.audit'::regclass AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c,LATERAL aclexplode(c.attacl) a
 WHERE c.attrelid='mdm_access.audit'::regclass AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
