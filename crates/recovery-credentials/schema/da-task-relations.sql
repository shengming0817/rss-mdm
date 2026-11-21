BEGIN;
ALTER TABLE rss_da.credential_runs ADD COLUMN da_execution jsonb, ADD COLUMN da_permit_until bigint NOT NULL DEFAULT 0, ADD COLUMN da_escrow_digest bytea CHECK(octet_length(da_escrow_digest)=32);
CREATE UNIQUE INDEX credential_da_unfinished ON rss_da.credential_runs(tenant_id,device)
 WHERE da_execution IS NOT NULL AND state <> '"applied"'::jsonb;
CREATE POLICY credential_agent_path ON rss_da.credential_runs AS RESTRICTIVE
 TO da_command_runtime,da_policy_runtime USING(da_execution IS NULL) WITH CHECK(da_execution IS NULL);
CREATE POLICY targeted_update ON rss_da.credential_runs AS RESTRICTIVE FOR UPDATE TO da_access
 USING(da_execution IS NOT NULL) WITH CHECK(da_execution IS NOT NULL);
GRANT UPDATE(state,result,da_permit_until,da_escrow_digest) ON rss_da.credential_runs TO da_access;
GRANT SELECT,INSERT ON rss_da.credential_runs TO da_identity_runtime;
CREATE POLICY credential_da_management ON rss_da.credential_runs AS RESTRICTIVE TO da_identity_runtime
 USING(da_execution IS NOT NULL) WITH CHECK(da_execution IS NOT NULL);

GRANT SELECT,INSERT ON rss_da.credential_runs,rss_da.credential_policy_recovery TO da_command_runtime,da_policy_runtime;
GRANT UPDATE(state,result,source_objects) ON rss_da.credential_runs TO da_command_runtime,da_policy_runtime;
GRANT UPDATE(gateway_accepted) ON rss_da.credential_runs TO da_command_runtime;
GRANT SELECT,INSERT ON rss_da.credential_agent_admission TO da_command_runtime;
GRANT UPDATE(policy_after) ON rss_da.credential_agent_admission TO da_command_runtime;
GRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON rss_da.credential_policy_recovery TO da_command_runtime;
GRANT UPDATE(input_revision) ON rss_da.credential_policy_recovery TO da_policy_runtime;
GRANT SELECT ON rss_da.credential_runs TO da_access;
CREATE FUNCTION rss_da.credential_save_retired_run(p_device uuid,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE rss_da.credential_runs a SET state=p_state
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.device=p_device AND a.id=p_run AND a.state=p_previous
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(
  SELECT FROM rss_da.agent_delivery d
  WHERE (d.tenant_id,d.agent_device)=
   (a.tenant_id,a.device)
   AND a.material_binding @> jsonb_build_object(
    'device',d.da_device,
    'subject',jsonb_build_object('kind','rss_login'))
   AND NOT d.enabled
  FOR SHARE OF d
 )
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION rss_da.credential_save_retired_run(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.credential_save_retired_run(uuid,uuid,jsonb,jsonb) TO da_access,da_command_runtime;
COMMIT;
