-- Installation receipt ownership and effective runtime authority, not database shape.
SELECT current_user='mdm_access' AND session_user=current_user
 AND EXISTS(SELECT 1 FROM pg_class c WHERE c.oid='public.mdm_migrations'::regclass
 AND c.relkind='r' AND c.relowner='mdm_owner'::regrole
 AND has_table_privilege(current_user,c.oid,'SELECT')
 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE
 (r.rolname=current_user OR pg_has_role(session_user,r.oid,'SET') OR pg_has_role(current_user,r.oid,'USAGE'))
 AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.oid=c.relowner
 OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
 WHERE a.grantee=0 OR (a.grantee<>c.relowner AND (a.is_grantable OR a.privilege_type<>'SELECT')))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute col,LATERAL aclexplode(col.attacl) a
 WHERE col.attrelid=c.oid AND (a.grantee=0 OR (a.grantee<>c.relowner AND (a.is_grantable OR a.privilege_type<>'SELECT')))))
