BEGIN;
GRANT SELECT,INSERT ON rss_da.credential_runs,rss_da.credential_policy_recovery TO da_command_runtime,da_policy_runtime;
GRANT UPDATE(state,result,source_objects) ON rss_da.credential_runs TO da_command_runtime,da_policy_runtime;
GRANT UPDATE(gateway_accepted) ON rss_da.credential_runs TO da_command_runtime;
GRANT SELECT,INSERT ON rss_da.credential_agent_admission TO da_command_runtime;
GRANT UPDATE(policy_after) ON rss_da.credential_agent_admission TO da_command_runtime;
GRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON rss_da.credential_policy_recovery TO da_command_runtime;
GRANT UPDATE(input_revision) ON rss_da.credential_policy_recovery TO da_policy_runtime;
GRANT SELECT ON rss_da.credential_runs TO da_access;
CREATE FUNCTION rss_da.credential_save_retired_run(p_registration uuid,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE rss_da.credential_runs a SET state=p_state
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.registration=p_registration AND a.id=p_run AND a.state=p_previous
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(
  SELECT FROM rss_da.agent_delivery d
  WHERE (d.tenant_id,d.agent_device,d.agent_registration,d.agent_generation)=
   (a.tenant_id,a.device,a.registration,a.generation)
   AND a.material_binding @> jsonb_build_object(
    'device',d.da_device,'registration',d.da_registration,'generation',d.da_generation,
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
