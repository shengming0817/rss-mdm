WITH execution_roles AS (SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')),
reachable AS (SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE')))
SELECT NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication)
AND NOT EXISTS(SELECT FROM pg_namespace n,reachable r WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(r.oid,n.oid,'CREATE'))
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='public.mdm_installation'::regclass
 AND c.relkind='r' AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND has_schema_privilege(current_user,c.relnamespace,'USAGE')
 AND NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT')<>(a.attname IN('instance_id','management_tenant_id')))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute col,LATERAL aclexplode(col.attacl) a WHERE col.attrelid=c.oid
 AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))))
