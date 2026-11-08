-- Registration retirement participates on the initiating audit connection.
BEGIN;
SET LOCAL check_function_bodies = false;
CREATE FUNCTION mdm_script.save_retired_run(p_device text,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE mdm_script.runs a SET state=p_state
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.device=p_device AND a.id=p_run AND a.state=p_previous
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(SELECT 1 FROM mdm_access.devices r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.device) AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id)))))
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION mdm_script.save_retired_run(text,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_script.save_retired_run(text,uuid,jsonb,jsonb) TO mdm_access,mdm_command_runtime;
COMMIT;
