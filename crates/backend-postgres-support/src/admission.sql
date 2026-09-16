WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=$1::text AND c.relkind='r'
), execution_roles AS (
 -- SET ROLE is authorized against session_user, not the current effective role.
 SELECT oid FROM pg_roles WHERE rolname=current_user
 OR pg_has_role(session_user,oid,'SET')
), reachable AS (
 -- Include inherited privileges of every executable role, also across mixed
 -- SET-only and INHERIT-only edges. MEMBER alone does not establish authority.
 SELECT r.* FROM pg_roles r WHERE EXISTS(
   SELECT 1 FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))
)
SELECT
 (SELECT array_agg(relname::text ORDER BY relname)=$2::text[] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=$1::text AND c.relkind NOT IN('r','i'))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname=$1::text)
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
 OR oid IN (SELECT relowner FROM tables) OR has_schema_privilege(oid,$1::text,'CREATE'))
 AND has_schema_privilege(current_user,$1::text,'USAGE')
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT t.relrowsecurity OR NOT t.relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT')
 OR NOT has_table_privilege(current_user,t.oid,'INSERT')
 OR EXISTS(SELECT 1 FROM reachable r
   WHERE has_table_privilege(r.oid,t.oid,'TRUNCATE,REFERENCES,TRIGGER,UPDATE,DELETE'))
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND lower(replace(regexp_replace(pg_get_expr(polwithcheck,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'))
 AND NOT EXISTS(SELECT 1 FROM tables t, LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n,LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
 WHERE n.nspname=$1::text AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <>
  ((t.relname::text || '.' || a.attname::text)=ANY($3::text[]))
 OR EXISTS(SELECT 1 FROM reachable r
   WHERE has_column_privilege(r.oid,t.oid,a.attnum,'REFERENCES')
   OR (has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE')
       AND NOT ((t.relname::text || '.' || a.attname::text)=ANY($3::text[]))))))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid,
 LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=0
 OR (acl.grantee IN(SELECT oid FROM reachable) AND acl.is_grantable))
