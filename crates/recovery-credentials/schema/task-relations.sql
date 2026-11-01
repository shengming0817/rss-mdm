BEGIN;
ALTER TABLE mdm_recovery_tasks.runs ADD FOREIGN KEY(tenant_id,policy_version) REFERENCES mdm_policy.versions(tenant_id,id);
ALTER TABLE mdm_recovery_tasks.runs ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);
ALTER TABLE mdm_recovery_tasks.runs ADD FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
ALTER TABLE mdm_recovery_tasks.agent_admission ADD FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
ALTER TABLE mdm_recovery_tasks.policy_recovery ADD FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id);
ALTER TABLE mdm_recovery_tasks.operations ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.command_authorities(tenant_id,device);
ALTER TABLE mdm_recovery_tasks.requests ADD FOREIGN KEY(tenant_id,operation) REFERENCES mdm_recovery_tasks.operations(tenant_id,id);
GRANT USAGE ON SCHEMA mdm_recovery_tasks TO mdm_command_runtime,mdm_policy_runtime,mdm_access;
GRANT SELECT,INSERT ON mdm_recovery_tasks.runs,mdm_recovery_tasks.policy_recovery TO mdm_command_runtime,mdm_policy_runtime;
GRANT UPDATE(state,result,source_objects) ON mdm_recovery_tasks.runs TO mdm_command_runtime,mdm_policy_runtime;
GRANT UPDATE(gateway_accepted) ON mdm_recovery_tasks.runs TO mdm_command_runtime;
GRANT SELECT ON mdm_recovery_tasks.runs,mdm_recovery_tasks.operations TO mdm_access;
GRANT SELECT,INSERT ON mdm_recovery_tasks.agent_admission,mdm_recovery_tasks.operations,mdm_recovery_tasks.requests TO mdm_command_runtime;
GRANT UPDATE(policy_after) ON mdm_recovery_tasks.agent_admission TO mdm_command_runtime;
GRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON mdm_recovery_tasks.policy_recovery TO mdm_command_runtime;
GRANT UPDATE(input_revision) ON mdm_recovery_tasks.policy_recovery TO mdm_policy_runtime;
GRANT UPDATE(authority,revision,observed_command_version,gateway_accepted,dispatch_failure,request) ON mdm_recovery_tasks.operations TO mdm_command_runtime;
GRANT EXECUTE ON FUNCTION mdm_recovery_tasks.native_status(uuid),mdm_recovery_tasks.retirement_commands(uuid,text),mdm_recovery_tasks.save_retired_command(uuid,uuid,bigint,bigint) TO mdm_access,mdm_command_runtime,mdm_policy_runtime;
COMMIT;

-- Registration retirement participates on the initiating audit connection.
BEGIN;
SET LOCAL check_function_bodies = false;
CREATE FUNCTION mdm_recovery_tasks.save_retired_run(p_registration uuid,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE mdm_recovery_tasks.runs a SET state=p_state
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.registration=p_registration AND a.id=p_run AND a.state=p_previous
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.registration) AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM mdm_access.devices d WHERE (d.tenant_id,d.id)=(r.tenant_id,r.device) AND d.retirement IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id)))))
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION mdm_recovery_tasks.save_retired_run(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_recovery_tasks.save_retired_run(uuid,uuid,jsonb,jsonb) TO mdm_access,mdm_command_runtime;
COMMIT;
