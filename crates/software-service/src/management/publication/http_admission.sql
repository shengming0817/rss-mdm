WITH reachable AS (
 SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'USAGE') OR pg_has_role(session_user,oid,'SET')
)
SELECT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=to_regclass('mdm_publication.operations') AND c.relkind='r'
 AND c.relrowsecurity AND c.relforcerowsecurity
 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.oid=c.relowner)
 AND has_schema_privilege(current_user,'mdm_publication','USAGE')
 AND has_table_privilege(current_user,c.oid,'SELECT') AND has_table_privilege(current_user,c.oid,'INSERT')
 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE has_table_privilege(r.oid,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'UPDATE,REFERENCES'))
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=c.oid AND contype='p' AND convalidated AND pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, actor, id)')
 AND (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)=1
 AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR (a.grantee<>c.relowner AND a.is_grantable)))
