WITH tables AS (SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_software' AND c.relkind='r'),
reachable AS (SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'MEMBER'))
SELECT (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['approvals','materials','operations','sources'] FROM tables)
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE NOT relrowsecurity OR NOT relforcerowsecurity OR relowner IN(SELECT oid FROM reachable)
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR NOT has_table_privilege(current_user,t.oid,'INSERT') OR has_table_privilege(current_user,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped AND (has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES') OR has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <> (t.relname IN('sources','approvals') AND a.attname='admission')))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE (SELECT count(*) FROM pg_policy p WHERE p.polrelid=t.oid)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=t.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
 AND NOT EXISTS(SELECT 1 FROM tables t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute c ON c.attrelid=t.oid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
