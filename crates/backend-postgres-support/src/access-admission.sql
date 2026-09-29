WITH contract AS (
 SELECT * FROM jsonb_to_recordset($2->'tables') AS t(schema text,"table" text,read_write boolean,updates jsonb,delete_policy text)
), schemas AS (SELECT DISTINCT schema FROM contract), relations AS (
 SELECT c.*, n.nspname AS schema FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN (SELECT schema FROM schemas)
), owned AS (
 SELECT c.*,t.read_write,t.updates,t.delete_policy FROM relations c JOIN contract t ON t.schema=c.schema AND t."table"=c.relname WHERE c.relkind='r'
), functions AS (
 SELECT * FROM jsonb_to_recordset($2->'functions') AS f(name text, search_path text)
)
SELECT current_user=$1 AND session_user=current_user
 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user) OR roleid=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND NOT has_database_privilege(current_user,current_database(),'CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_temp_%' AND has_schema_privilege(current_user,oid,'CREATE'))
 AND NOT EXISTS(SELECT 1 FROM schemas WHERE NOT has_schema_privilege(current_user,schema,'USAGE'))
 AND (SELECT count(*) FROM owned)=(SELECT count(*) FROM contract)
 AND NOT EXISTS(SELECT 1 FROM relations WHERE relkind NOT IN('r','i') OR relkind='r' AND oid NOT IN(SELECT oid FROM owned))
 AND NOT EXISTS(SELECT 1 FROM owned WHERE NOT relrowsecurity OR NOT relforcerowsecurity OR relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  OR has_table_privilege(current_user,oid,'SELECT')<>read_write
  OR NOT read_write AND has_any_column_privilege(current_user,oid,'SELECT')
  OR has_table_privilege(current_user,oid,'INSERT')<>read_write
  OR NOT read_write AND has_any_column_privilege(current_user,oid,'INSERT')
  OR has_table_privilege(current_user,oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_table_privilege(current_user,oid,'DELETE')<>(delete_policy IS NOT NULL))
 AND NOT EXISTS(SELECT 1 FROM owned c JOIN pg_attribute a ON a.attrelid=c.oid WHERE a.attnum>0 AND NOT a.attisdropped
  AND (has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(c.updates ? a.attname::text)
   OR has_column_privilege(current_user,c.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM relations c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n,LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname IN(SELECT schema FROM schemas) AND (a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM relations c JOIN pg_attribute col ON col.attrelid=c.oid,LATERAL aclexplode(col.attacl) a WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND (a.is_grantable OR a.privilege_type='REFERENCES'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT IN(SELECT schema FROM schemas)
  AND NOT ($2->'verified_schemas' ? n.nspname::text) AND NOT ($2->'external_relations' ? (n.nspname||'.'||c.relname))
  AND c.relkind IN('r','p','v','m','f') AND (has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('pg_catalog','information_schema') AND c.relkind='S' AND CASE WHEN c.relkind='S' THEN has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE') ELSE false END)
 AND (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN('pg_catalog','information_schema') AND has_function_privilege(current_user,p.oid,'EXECUTE'))=(SELECT count(*) FROM functions)
 AND NOT EXISTS(SELECT 1 FROM functions f WHERE (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname||'.'||p.proname=f.name AND p.prosecdef AND p.proowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user) AND p.proconfig @> ARRAY[f.search_path] AND has_function_privilege(current_user,p.oid,'EXECUTE'))<>1)
 AND NOT EXISTS(SELECT 1 FROM owned c WHERE
  (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)<>CASE WHEN c.delete_policy IS NULL THEN 1 ELSE 2 END
  OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid] AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid' AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
  OR c.delete_policy IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='expired_only' AND p.polcmd='d' AND NOT p.polpermissive AND p.polroles=ARRAY[0::oid] AND p.polwithcheck IS NULL AND lower(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'))=c.delete_policy))
