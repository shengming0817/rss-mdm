WITH tables AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='mdm_apple'
), updates(relation,col) AS (VALUES
 ('psso_sources','registration'),('psso_sources','parent'),('psso_sources','version'),('psso_sources','revoked'),('psso_sources','signing_kid'),('psso_sources','document'),('psso_challenges','consumed'),
 ('ade_sync_devices','operation_date'),('ade_sync_devices','deleted'),('ade_sync_devices','remote_profile'),('ade_servers','revision'),('ade_servers','enabled'),('ade_servers','server_uuid'),('ade_servers','org_id'),('ade_servers','key_id'),('ade_servers','certificate'),('ade_servers','private_key'),('ade_servers','token'),('ade_servers','token_revision'),('ade_servers','token_expires'),('ade_servers','verified'),('ade_servers','token_invalid'),('ade_servers','cursor'),('ade_servers','synced_at'),('ade_servers','next_sync'),('ade_profiles','revision'),('ade_profiles','configuration'),('ade_profiles','remote_uuid'),('ade_devices','operation_date'),('ade_devices','deleted'),('ade_devices','seen_run'),('ade_devices','remote_profile'),('ade_devices','assignment_revision'),('ade_devices','observed_at'),('ade_operations','state'),('ade_operations','result'),('ade_operations','cursor'),('ade_operations','cursor_digests'),('ade_operations','full_sync'),('ade_operations','lease'),('ade_operations','lease_until'),('ade_operations','next_attempt'),('ade_operations','attempts'),('ade_enrollments','revoked'),
 ('account_configuration','operation'),('account_bindings','operation'),('account_configuration','domain'),('account_configuration','server_uuid'),('account_configuration','signing_key'),('account_configuration','enabled'),('account_configuration','revision'),
 ('account_bindings','principal'),('account_bindings','instance'),('account_bindings','enabled'),('account_bindings','revision'),
 ('account_flows','account'),('account_flows','binding_revision'),('account_flows','cookie_hash'),('account_flows','enrollment'),('account_flows','authorization_version'),('account_flows','token_hash'),('account_flows','material'),('account_flows','profile'),('account_flows','revoked'),
 ('scep_attempts','state'),('scep_attempts','transaction_id'),('scep_attempts','csr_digest'),('scep_attempts','spki'),('scep_attempts','serial'),('scep_attempts','fingerprint'),('scep_attempts','certificate'),('scep_attempts','registration'),('scep_attempts','not_before'),('scep_attempts','not_after'),
 ('devices','state'),('devices','identity_health'),('devices','bootstrap'),('devices','bootstrap_revision'),
 ('channels','state'),('channels','material'),('channels','material_digest'),('channels','token_revision'),('channels','next_push'),('channels','push_id'),('channels','push_lease_until'),('channels','push_status'),('channels','push_outcome'),('channels','push_failures'),
 ('declarations','retired_at'),('profiles','retired_at'),('attempts','native_outcome'),('attempts','accepted'),('attempts','state'),('attempts','response'),('attempts','response_digest'),('attempts','received_at'),('attempts','next_attempt')
)
SELECT has_schema_privilege(current_user,'mdm_apple','USAGE')
 AND (SELECT array_agg(relname::text ORDER BY relname)=ARRAY['account_bindings','account_configuration','account_flows','ade_devices','ade_enrollments','ade_operations','ade_profiles','ade_servers','ade_sync_devices','attempts','channels','declarations','devices','organizations','profiles','psso_challenges','psso_sources','psso_tokens','scep_attempts','status_reports','trust_deliveries'] FROM tables WHERE relkind='r')
 AND NOT EXISTS(SELECT 1 FROM tables WHERE relkind NOT IN ('r','i'))
 AND NOT EXISTS(SELECT 1 FROM tables t WHERE relkind='r' AND (
  NOT relrowsecurity OR NOT relforcerowsecurity OR relpersistence<>'p' OR relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  OR NOT has_table_privilege(current_user,oid,'SELECT')
  OR has_table_privilege(current_user,oid,'INSERT')<>(relname NOT IN('profiles','declarations','status_reports'))
  OR has_table_privilege(current_user,oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_table_privilege(current_user,oid,'DELETE')<>(relname IN('account_flows','ade_sync_devices','psso_challenges','psso_tokens'))
  OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=t.oid AND polname='tenant' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
    AND lower(replace(regexp_replace(pg_get_expr(polqual,polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
    AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid))))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid WHERE t.relkind='r' AND a.attnum>0 AND NOT a.attisdropped AND (
  has_column_privilege(current_user,t.oid,a.attnum,'UPDATE')<>EXISTS(SELECT 1 FROM updates u WHERE u.relation=t.relname AND u.col=a.attname)
  OR NOT has_column_privilege(current_user,t.oid,a.attnum,'SELECT')
  OR has_column_privilege(current_user,t.oid,a.attnum,'INSERT')<>(t.relname NOT IN('profiles','declarations','status_reports'))
  OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM tables) AND NOT tgisinternal)
 AND NOT EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class IN(SELECT oid FROM tables))
 AND NOT EXISTS(SELECT 1 FROM tables t, LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n,LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='mdm_apple' AND (a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable))
 AND NOT EXISTS(SELECT 1 FROM tables t JOIN pg_attribute c ON c.attrelid=t.oid,LATERAL aclexplode(c.attacl) a WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM (VALUES
  ('mdm.inventory'::regclass)
 ) evidence(oid) WHERE NOT has_table_privilege(current_user,evidence.oid,'SELECT')
  OR has_table_privilege(current_user,evidence.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_any_column_privilege(current_user,evidence.oid,'INSERT,UPDATE,REFERENCES'))
