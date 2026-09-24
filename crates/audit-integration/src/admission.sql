WITH relation AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='mdm_audit' AND c.relname='receipts' AND c.relkind='r'
)
SELECT
 (SELECT count(*)=1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_audit' AND c.relkind IN('r','p','v','m','f'))
 AND has_schema_privilege(current_user,'mdm_audit','USAGE')
 AND NOT has_schema_privilege(current_user,'mdm_audit','CREATE')
 AND (SELECT relrowsecurity AND relforcerowsecurity
  AND NOT pg_has_role(current_user,relowner,'MEMBER')
  AND has_table_privilege(current_user,oid,'SELECT,INSERT')
  AND NOT has_table_privilege(current_user,oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,oid,'UPDATE,REFERENCES') FROM relation)
 AND (SELECT array_agg(a.attname::text ORDER BY a.attnum)=ARRAY['tenant_id','source_id','event_id','fingerprint','canonical']
  AND bool_and(a.attnotnull AND a.atttypid=CASE a.attname WHEN 'tenant_id' THEN 'uuid'::regtype WHEN 'source_id' THEN 'text'::regtype WHEN 'event_id' THEN 'text'::regtype ELSE 'bytea'::regtype END)
  FROM pg_attribute a JOIN relation r ON r.oid=a.attrelid WHERE a.attnum>0 AND NOT a.attisdropped)
 AND (SELECT count(*)=1 AND bool_and(p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
  AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
  AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN relation r ON r.oid=p.polrelid)
 AND NOT EXISTS(SELECT 1 FROM pg_trigger t JOIN relation r ON r.oid=t.tgrelid WHERE NOT t.tgisinternal)
 AND NOT EXISTS(SELECT 1 FROM pg_rewrite w JOIN relation r ON r.oid=w.ev_class)
 AND NOT EXISTS(SELECT 1 FROM relation r,LATERAL aclexplode(coalesce(r.relacl,acldefault('r',r.relowner))) a WHERE a.grantee=0 OR a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c JOIN relation r ON r.oid=c.attrelid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR a.is_grantable)
 AND (SELECT count(*)=3 AND bool_and(c.convalidated AND (
  c.contype='p' AND c.conkey=ARRAY[1,2,3]::smallint[]
  OR c.contype='c' AND c.conkey=ARRAY[4]::smallint[] AND lower(regexp_replace(pg_get_expr(c.conbin,c.conrelid),'[[:space:]()]','','g'))='octet_lengthfingerprint=32'
  OR c.contype='c' AND c.conkey=ARRAY[5]::smallint[] AND lower(regexp_replace(pg_get_expr(c.conbin,c.conrelid),'[[:space:]()]','','g'))='octet_lengthcanonical>=1andoctet_lengthcanonical<=131072'
 )) FROM pg_constraint c JOIN relation r ON r.oid=c.conrelid)
 AND EXISTS(SELECT 1 FROM pg_index i JOIN relation r ON r.oid=i.indrelid WHERE i.indisprimary AND i.indisvalid AND i.indisready AND i.indislive)
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n,LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='mdm_audit' AND (a.grantee=0 OR a.is_grantable))
