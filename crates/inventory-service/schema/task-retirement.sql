-- Registration retirement participates on the initiating audit connection.
BEGIN;
SET LOCAL check_function_bodies = false;
CREATE FUNCTION mdm_inventory.save_retired_collection_agent(p_device uuid,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE mdm_inventory.collection_tasks a SET agent_state=p_state
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.device=p_device AND a.id=p_run AND a.agent_state=p_previous
 AND a.agent_state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.agent_state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(SELECT 1 FROM mdm_access.devices r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.device) AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id)))))
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION mdm_inventory.save_retired_collection_agent(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_inventory.save_retired_collection_agent(uuid,uuid,jsonb,jsonb) TO mdm_access,mdm_command_runtime;
CREATE FUNCTION mdm_inventory.cancel_retired_collection(p_device uuid,p_run uuid,p_previous text) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE mdm_inventory.collection_tasks a SET native_delivery='cancelled'
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.device=p_device AND a.id=p_run AND a.channel='mdm'
 AND a.native_delivery=p_previous AND a.native_delivery IN('queued','prepared')
 AND EXISTS(SELECT 1 FROM mdm_access.devices r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.device) AND (r.state<>'active' OR (r.retirement IS NOT NULL AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id)))))
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION mdm_inventory.cancel_retired_collection(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_inventory.cancel_retired_collection(uuid,uuid,text) TO mdm_access,mdm_command_runtime;
COMMIT;
