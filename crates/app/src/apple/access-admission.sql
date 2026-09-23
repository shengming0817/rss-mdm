WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_apple'
), updates(relation,col) AS (VALUES
 ('scep_attempts','state'),('scep_attempts','transaction_id'),('scep_attempts','csr_digest'),('scep_attempts','spki'),('scep_attempts','serial'),('scep_attempts','fingerprint'),('scep_attempts','certificate'),('scep_attempts','registration'),('scep_attempts','not_before'),('scep_attempts','not_after'),
 ('devices','state'),('devices','token'),('devices','magic'),('devices','token_revision'),('devices','next_push'),('devices','push_id'),('devices','push_lease_until'),('devices','push_status'),('devices','push_outcome'),('devices','push_failures'),('devices','identity_health'),
 ('attempts','state'),('attempts','response'),('attempts','response_digest'),('attempts','received_at'),('attempts','next_attempt')
)
SELECT has_schema_privilege(current_user,'mdm_apple','USAGE')
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['attempts','devices','profiles','scep_attempts'] FROM tables WHERE relkind='r')
 AND NOT EXISTS(SELECT 1 FROM tables WHERE relkind NOT IN ('r','i'))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE relkind='r' AND (
  NOT relrowsecurity OR NOT relforcerowsecurity OR relpersistence<>'p' OR relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  OR has_table_privilege(current_user,oid,'SELECT')<>(relname<>'profiles')
  OR has_table_privilege(current_user,oid,'INSERT')<>(relname<>'profiles')
  OR has_table_privilege(current_user,oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
    AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
    AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid))))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE t.relkind='r' AND a.attnum>0 AND NOT a.attisdropped AND (
  has_column_privilege(current_user,t.oid,a.attnum,'UPDATE')<>EXISTS(SELECT 1 FROM updates u WHERE u.relation=t.relname AND u.col=a.attname)
  OR has_column_privilege(current_user,t.oid,a.attnum,'SELECT')<>(t.relname<>'profiles')
  OR has_column_privilege(current_user,t.oid,a.attnum,'INSERT')<>(t.relname<>'profiles')
  OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM tables) AND NOT tgisinternal)
 AND NOT EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class IN(SELECT oid FROM tables))
 AND NOT EXISTS(SELECT 1 FROM tables t, LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n,LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='mdm_apple' AND (a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute c ON c.attrelid=t.oid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
