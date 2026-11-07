-- Immutable associations and narrow cross-owner request/task coordinates only.
WITH expected(name,reads) AS (VALUES
 ('mdm_devices.unmanage_runs',NULL::text[]),
 ('mdm_script.runs',NULL::text[]),
 ('mdm_inventory.collection_tasks',NULL::text[]),
 ('mdm_planning.configuration_operations',NULL::text[]),
 ('mdm_assets.operations',NULL::text[]),
 ('mdm_devices.control_requests',NULL::text[]),
 ('mdm_devices.control_operations',NULL::text[]),
 ('mdm_policy.versions',NULL::text[]),
 ('mdm_software_deployment.operations',NULL::text[]),
 ('mdm_software_deployment.action_runs',NULL::text[]),
 ('mdm_registration_tasks.operations',NULL::text[]),
 ('mdm_registration_tasks.runs',NULL::text[]),
 ('mdm_recovery_tasks.operations',NULL::text[]),
 ('mdm_recovery_tasks.runs',NULL::text[]),
 ('mdm_software_deployment.requests',ARRAY['tenant_id','actor','id','operation']::text[]),
 ('mdm_registration_tasks.requests',ARRAY['tenant_id','actor','id','operation']::text[]),
 ('mdm_recovery_tasks.requests',ARRAY['tenant_id','actor','id','operation']::text[]),
 ('rss_da.access_runs',NULL::text[]),
 ('rss_da.credential_runs',NULL::text[])
), relations AS (
 SELECT c.*,e.reads FROM expected e JOIN pg_class c ON c.oid=to_regclass(e.name)
)
SELECT (SELECT count(*) FROM relations)=(SELECT count(*) FROM expected)
 AND NOT EXISTS(SELECT 1 FROM relations c WHERE c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
  OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  OR NOT has_schema_privilege(current_user,c.relnamespace,'USAGE')
  OR CASE WHEN c.reads IS NULL THEN NOT has_table_privilege(current_user,c.oid,'SELECT') ELSE
   has_table_privilege(current_user,c.oid,'SELECT')
   OR (SELECT count(*) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attname::text=ANY(c.reads))<>cardinality(c.reads)
   OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
    AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT') IS DISTINCT FROM (a.attname::text=ANY(c.reads))) END
  OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT 1 FROM relations c JOIN pg_attribute col ON col.attrelid=c.oid,LATERAL aclexplode(col.attacl) a
  WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM relations c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM relations c WHERE
 (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant'
 AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
