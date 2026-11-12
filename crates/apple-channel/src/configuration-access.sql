-- Exact Policy consumer privileges; source: PostgreSQL column GRANT semantics.
WITH required(relation,col,insertable,updatable) AS (VALUES
 ('mdm_apple.declarations','tenant_id',false,false),
 ('mdm_apple.declarations','operation',false,false),
 ('mdm_apple.declarations','device',false,false),
 ('mdm_apple.declarations','user_key',false,false),
 ('mdm_apple.declarations','owner',false,false),
 ('mdm_apple.declarations','retired_at',false,false),
 ('mdm_apple.declarations','snapshot',false,false),
 ('mdm_apple.profiles','tenant_id',true,false),
 ('mdm_apple.profiles','operation',true,false),
 ('mdm_apple.profiles','device',true,false),
 ('mdm_apple.profiles','user_key',true,false),
 ('mdm_apple.profiles','identifier',true,false),
 ('mdm_apple.profiles','profile',true,false),
 ('mdm_apple.profiles','version',true,false),
 ('mdm_apple.profiles','present',true,false),
 ('mdm_apple.profiles','manifest',false,false),
 ('mdm_apple.profiles','manifest_digest',false,false),
 ('mdm_apple.profiles','manifest_cipher_digest',false,false),
 ('mdm_apple.profiles','dispatched_at',false,false),
 ('mdm_apple.profiles','observed_at',false,false),
 ('mdm_apple.profiles','retired_at',false,true)
), relations AS (SELECT DISTINCT relation FROM required)
SELECT current_user='mdm_policy_runtime' AND session_user=current_user
 AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 AND NOT EXISTS(SELECT FROM relations r LEFT JOIN pg_class c ON c.oid=to_regclass(r.relation)
  WHERE c.oid IS NULL OR c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
   OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
   OR NOT has_schema_privilege(current_user,c.relnamespace,'USAGE')
   OR has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)<>1
   OR NOT EXISTS(SELECT FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
    AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
    AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
 AND NOT EXISTS(SELECT FROM required r LEFT JOIN pg_attribute a ON a.attrelid=to_regclass(r.relation) AND a.attname=r.col AND a.attnum>0 AND NOT a.attisdropped WHERE a.attnum IS NULL)
 AND NOT EXISTS(SELECT FROM relations r JOIN pg_attribute a ON a.attrelid=to_regclass(r.relation) AND a.attnum>0 AND NOT a.attisdropped
  LEFT JOIN required q ON q.relation=r.relation AND q.col=a.attname
  WHERE has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')<>(q.col IS NOT NULL)
   OR has_column_privilege(current_user,a.attrelid,a.attnum,'INSERT')<>coalesce(q.insertable,false)
   OR has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE')<>coalesce(q.updatable,false)
   OR has_column_privilege(current_user,a.attrelid,a.attnum,'REFERENCES'))
 AND NOT EXISTS(SELECT FROM relations r JOIN pg_class c ON c.oid=to_regclass(r.relation),LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable))
 AND NOT EXISTS(SELECT FROM relations r JOIN pg_attribute col ON col.attrelid=to_regclass(r.relation),LATERAL aclexplode(col.attacl) a
  WHERE a.grantee=0 OR (a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable));
