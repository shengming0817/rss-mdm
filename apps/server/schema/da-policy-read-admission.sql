SELECT EXISTS (
 SELECT FROM pg_class r WHERE r.oid='mdm_policy.versions'::regclass AND relkind='r'
 AND relrowsecurity AND relforcerowsecurity
 AND has_schema_privilege(current_user,'mdm_policy','USAGE')
 AND NOT has_table_privilege(current_user,r.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,r.oid,'INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS (
  SELECT FROM pg_attribute a WHERE a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped
  AND has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')
      <> (a.attname IN ('tenant_id','id','policy'))
 )
)
