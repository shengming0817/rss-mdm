WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_management' AND c.relkind='r'
), reachable AS (
 SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'MEMBER')
)
SELECT
 current_setting('transaction_isolation')='serializable'
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['operations','plan_references','previews','resource_references','scope_versions','scopes'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
 OR oid IN(SELECT relowner FROM tables))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR NOT has_table_privilege(current_user,t.oid,'INSERT')
 OR has_table_privilege(current_user,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <> (t.relname='scopes' AND a.attname IN('revision','deleted')) OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(current_user,n.oid,'CREATE'))
 AND has_schema_privilege(current_user,'mdm_management','USAGE')
 AND has_table_privilege(current_user,'mdm_access.audit','INSERT')
 AND NOT has_table_privilege(current_user,'mdm_access.audit','SELECT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND c.relkind IN('r','v','m','f')
 AND n.nspname NOT IN('mdm_management','mdm_group','mdm_policy','mdm_resource')
 AND (n.nspname,c.relname) NOT IN(('mdm_access','audit'),('mdm_access','devices'),('mdm_access','registrations'),('mdm_access','report_sources'),('mdm_access','collection_runs'),('mdm','inventory'),('mdm_software_composition','subjects'),('rss_transactional_messaging','policy'),('rss_transactional_messaging','outbox'))
 AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname,c.relname) IN(('mdm_access','devices'),('mdm_access','registrations'),('mdm_access','report_sources'),('mdm_access','collection_runs'),('mdm','inventory'),('mdm_software_composition','subjects'))
 AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner IN(SELECT oid FROM reachable) OR NOT has_table_privilege(current_user,c.oid,'SELECT') OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND p.oid NOT IN ('rss_transactional_messaging.check_execution()'::regprocedure,'rss_transactional_messaging.prepare_outbox_partitions(jsonb)'::regprocedure,'rss_transactional_messaging.append_outbox(bytea,jsonb)'::regprocedure) AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg_%' AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM tables t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute c ON c.attrelid=t.oid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
