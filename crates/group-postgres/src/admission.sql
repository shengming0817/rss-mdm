WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_group' AND c.relkind='r'
), reachable AS (
 SELECT * FROM pg_roles WHERE oid=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 OR pg_has_role(current_user,oid,'MEMBER')
)
SELECT
 (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['deltas','groups','members','operations','rules'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_group' AND c.relkind NOT IN('r','i'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='mdm_group')
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
 OR oid IN (SELECT relowner FROM tables) OR has_schema_privilege(oid,'mdm_group','CREATE'))
 AND has_schema_privilege(current_user,'mdm_group','USAGE')
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT t.relrowsecurity OR NOT t.relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT')
 OR NOT has_table_privilege(current_user,t.oid,'INSERT')
 OR has_table_privilege(current_user,t.oid,'TRUNCATE,REFERENCES,TRIGGER,UPDATE')
 OR has_table_privilege(current_user,t.oid,'DELETE')<>(t.relname='members')
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'))
 AND NOT EXISTS(SELECT 1 FROM tables t, LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n,LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
 WHERE n.nspname='mdm_group' AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <>
  (t.relname='groups' AND a.attname IN('name','description','revision','member_version','member_count','rule_version','deleted')
  OR t.relname='operations' AND a.attname IN('state','receipt','result','result_digest','failure','completed_at'))
 OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid,
 LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=0
 OR (acl.grantee IN(SELECT oid FROM reachable) AND acl.is_grantable))
