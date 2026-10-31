-- Fresh installation: agent-channel owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

ALTER TABLE ONLY mdm_agent.bindings
    ADD CONSTRAINT agent_bindings_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

GRANT USAGE ON SCHEMA mdm_agent TO mdm_access;
GRANT USAGE ON SCHEMA mdm_agent TO mdm_policy_runtime,mdm_scope_runtime,mdm_inventory_runtime,mdm_telemetry_runtime;
GRANT USAGE ON SCHEMA mdm_agent TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_agent.bindings TO mdm_access;
GRANT SELECT ON TABLE mdm_agent.bindings TO mdm_policy_runtime,mdm_scope_runtime,mdm_inventory_runtime,mdm_telemetry_runtime;
GRANT SELECT ON TABLE mdm_agent.bindings TO mdm_command_runtime;
GRANT UPDATE(execution_context) ON TABLE mdm_agent.bindings TO mdm_command_runtime,mdm_policy_runtime;

ALTER TABLE ONLY mdm_agent.task_attempts
    ADD CONSTRAINT task_attempts_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);
GRANT SELECT,INSERT ON TABLE mdm_agent.task_attempts TO mdm_command_runtime;
GRANT UPDATE(permit) ON TABLE mdm_agent.task_attempts TO mdm_command_runtime;
GRANT SELECT ON mdm_agent.task_attempts TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_agent.task_receipts,mdm_agent.task_polls TO mdm_command_runtime;
GRANT UPDATE(cancellation_after,offer_after_at,offer_after_id) ON mdm_agent.task_polls TO mdm_command_runtime;
GRANT UPDATE(announcement) ON mdm_agent.bindings TO mdm_command_runtime;
ALTER TABLE mdm_agent.task_receipts ADD FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
ALTER TABLE mdm_agent.task_polls ADD FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
-- Task Trust checks live Agent signature references without reading task payloads.
CREATE FUNCTION mdm_agent.pending_task_signatures(p_tenant uuid, p_key text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'task signature tenant mismatch' USING ERRCODE='42501';
 END IF;
 RETURN EXISTS(SELECT 1 FROM mdm_agent.task_attempts a WHERE a.tenant_id=p_tenant AND a.deadline>extract(epoch FROM clock_timestamp()) AND (a.offer->>'keyId'=p_key OR a.permit->>'keyId'=p_key));
END $$;
REVOKE ALL ON FUNCTION mdm_agent.pending_task_signatures(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_agent.pending_task_signatures(uuid,text) TO mdm_access;

COMMIT;
