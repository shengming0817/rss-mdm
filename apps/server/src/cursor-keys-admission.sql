-- Host-owned immutable tenant cursor secret; Access is the sole runtime writer.
WITH target AS (
 SELECT * FROM pg_class WHERE oid=to_regclass('public.mdm_cursor_keys')
), allowed AS (
 SELECT oid FROM pg_roles WHERE rolname IN ('mdm_owner','mdm_access')
)
SELECT current_user='mdm_access' AND session_user=current_user
 AND (SELECT count(*)=1 AND bool_and(relkind='r' AND relpersistence='p'
  AND relrowsecurity AND relforcerowsecurity AND pg_get_userbyid(relowner)='mdm_owner') FROM target)
 AND has_table_privilege(current_user,'public.mdm_cursor_keys','SELECT')
 AND has_table_privilege(current_user,'public.mdm_cursor_keys','INSERT')
 AND NOT has_table_privilege(current_user,'public.mdm_cursor_keys','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,'public.mdm_cursor_keys','UPDATE,REFERENCES')
 AND (SELECT count(*)=2 AND bool_and(attnotnull AND
  ((attname='tenant_id' AND atttypid='uuid'::regtype) OR (attname='secret' AND atttypid='bytea'::regtype)))
  FROM pg_attribute WHERE attrelid='public.mdm_cursor_keys'::regclass AND attnum>0 AND NOT attisdropped)
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.mdm_cursor_keys'::regclass
  AND contype='c' AND convalidated AND pg_get_constraintdef(oid)='CHECK ((octet_length(secret) = 32))')
 AND EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid='public.mdm_cursor_keys'::regclass
  AND i.indisprimary AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate
  AND i.indpred IS NULL AND i.indexprs IS NULL
  AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality)
   FROM unnest(i.indkey::smallint[]) WITH ORDINALITY k(num,ordinality)
   JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.num
   WHERE k.ordinality<=i.indnkeyatts)=ARRAY['tenant_id'])
 AND (SELECT count(*)=1 AND bool_and(polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
  AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
  AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid))
  FROM pg_policy WHERE polrelid='public.mdm_cursor_keys'::regclass)
 AND NOT EXISTS(SELECT 1 FROM target t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a
  WHERE a.grantee NOT IN(SELECT oid FROM allowed) OR (a.grantee<>t.relowner AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c,LATERAL aclexplode(c.attacl) a
  WHERE c.attrelid='public.mdm_cursor_keys'::regclass AND (a.grantee NOT IN(SELECT oid FROM allowed) OR a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolcanlogin AND NOT r.rolsuper
  AND r.oid NOT IN(SELECT oid FROM allowed)
  AND (has_table_privilege(r.oid,'public.mdm_cursor_keys','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege(r.oid,'public.mdm_cursor_keys','SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.mdm_cursor_keys'::regclass AND NOT tgisinternal)
 AND NOT EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class='public.mdm_cursor_keys'::regclass)
