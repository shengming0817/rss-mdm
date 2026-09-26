WITH tables AS (SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_software' AND c.relkind='r'),
execution_roles AS (
 -- SET ROLE is authorized against the original login role, including after SET ROLE.
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')
), reachable AS (
 SELECT r.* FROM pg_roles r WHERE EXISTS(
  SELECT 1 FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))
)
SELECT (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['approvals','materials','operations','sources'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR has_schema_privilege(oid,'mdm_software','CREATE'))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT relrowsecurity OR NOT relforcerowsecurity OR relowner IN(SELECT oid FROM reachable)
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR NOT has_table_privilege(current_user,t.oid,'INSERT') OR EXISTS(SELECT 1 FROM reachable r WHERE has_table_privilege(r.oid,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <> (t.relname IN('sources','approvals') AND a.attname='admission')
 OR EXISTS(SELECT 1 FROM reachable r WHERE has_column_privilege(r.oid,t.oid,a.attnum,'REFERENCES')
 OR (has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE') AND NOT (t.relname IN('sources','approvals') AND a.attname='admission')))))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE (SELECT count(*) FROM pg_policy p WHERE p.polrelid=t.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=t.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
 AND NOT EXISTS(SELECT 1 FROM tables t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute c ON c.attrelid=t.oid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
