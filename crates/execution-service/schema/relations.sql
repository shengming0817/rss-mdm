-- Fresh installation: execution owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;



ALTER TABLE ONLY mdm_commands.agent_admission
    ADD CONSTRAINT agent_admission_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices(tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_tenant_id_policy_version_fkey FOREIGN KEY (tenant_id, policy_version) REFERENCES mdm_policy.versions(tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);













ALTER TABLE ONLY mdm_commands.operations
    ADD CONSTRAINT operations_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.command_authorities(tenant_id, device);

ALTER TABLE ONLY mdm_commands.operations
    ADD CONSTRAINT operations_tenant_id_policy_version_fkey FOREIGN KEY (tenant_id, policy_version) REFERENCES mdm_policy.versions(tenant_id, id);

ALTER TABLE ONLY mdm_commands.policy_recovery
    ADD CONSTRAINT policy_recovery_tenant_id_policy_fkey FOREIGN KEY (tenant_id, policy) REFERENCES mdm_policy.policies(tenant_id, id);

ALTER TABLE ONLY mdm_commands.requests
    ADD CONSTRAINT requests_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_commands.operations(tenant_id, id);





GRANT USAGE ON SCHEMA mdm_commands TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_commands TO mdm_policy_runtime;



GRANT SELECT,INSERT ON TABLE mdm_commands.agent_admission TO mdm_command_runtime;


GRANT UPDATE(policy_after) ON TABLE mdm_commands.agent_admission TO mdm_command_runtime;


GRANT SELECT,INSERT ON TABLE mdm_commands.action_receipts TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(state) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(result) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT UPDATE(invocation,source_objects) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;









































GRANT SELECT,INSERT ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_commands.operations TO mdm_policy_runtime;

GRANT UPDATE(authority) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT UPDATE(revision) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted,dispatch_failure) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.policy_recovery TO mdm_command_runtime;

GRANT UPDATE(recovery_after,target_after,input_revision,input_consumed,input_window) ON TABLE mdm_commands.policy_recovery TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.requests TO mdm_command_runtime;





























GRANT USAGE ON SCHEMA mdm_commands TO mdm_access;

GRANT SELECT ON TABLE mdm_commands.operations TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_commands.installation_status(uuid) TO mdm_access,mdm_command_runtime;

GRANT SELECT,INSERT ON mdm_commands.output_chunks TO mdm_command_runtime;










GRANT SELECT ON mdm_commands.action_runs TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_commands.windows_pending_operations(uuid,bigint,uuid) TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_commands.windows_wake_candidates(uuid) TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_commands.retirement_commands(uuid,text),mdm_commands.save_retired_command(uuid,uuid,bigint,bigint) TO mdm_access,mdm_command_runtime;
GRANT EXECUTE ON FUNCTION mdm_commands.save_retired_action(uuid,uuid,jsonb,jsonb) TO mdm_access,mdm_command_runtime;
GRANT UPDATE(software_effect) ON mdm_commands.action_runs TO mdm_command_runtime;
COMMIT;





ALTER TABLE mdm_commands.software_stage_stats ADD FOREIGN KEY(tenant_id,version) REFERENCES mdm_policy.versions(tenant_id,id);
GRANT SELECT,INSERT ON mdm_commands.software_stage_stats TO mdm_command_runtime;
GRANT UPDATE(gate_open,input,cursor,ready,counts,generation,membership_complete) ON mdm_commands.software_stage_stats TO mdm_command_runtime;
GRANT SELECT ON mdm_commands.software_binding_revisions TO mdm_command_runtime;
CREATE TRIGGER software_bindings AFTER INSERT OR UPDATE OR DELETE ON mdm_agent.bindings FOR EACH ROW EXECUTE FUNCTION mdm_commands.advance_software_bindings();

ALTER TABLE mdm_commands.software_stats_members ADD FOREIGN KEY(tenant_id,version,stage) REFERENCES mdm_commands.software_stage_stats(tenant_id,version,stage);
ALTER TABLE mdm_commands.software_result_changes ADD FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id);
GRANT SELECT,INSERT ON mdm_commands.software_stats_members TO mdm_command_runtime;
GRANT UPDATE(generation,target,counts,waiting_until) ON mdm_commands.software_stats_members TO mdm_command_runtime;
GRANT SELECT ON mdm_commands.software_result_changes,mdm_commands.software_binding_changes TO mdm_command_runtime;

ALTER TABLE mdm_commands.native_checkins ADD FOREIGN KEY (tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
GRANT SELECT,INSERT ON mdm_commands.native_checkins TO mdm_command_runtime;
GRANT UPDATE(active_event,active_at,policy_after,pending_event,pending_at) ON mdm_commands.native_checkins TO mdm_command_runtime;


GRANT UPDATE(access_binding) ON mdm_commands.action_runs TO mdm_command_runtime;
GRANT SELECT ON mdm_policy.policies,mdm_policy.versions TO mdm_access;


-- Policy authors may announce changed desired work, never consume or complete it.
GRANT SELECT(tenant_id,policy,input_revision),INSERT(tenant_id,policy,input_revision),UPDATE(input_revision) ON mdm_commands.policy_recovery TO mdm_policy_runtime;

-- Explicit integration privileges owned by this capability.






-- Execution intent participation by the Policy transaction owner.
GRANT SELECT,INSERT ON mdm_commands.operations TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_commands.requests TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_commands.action_receipts TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_commands.policy_recovery TO mdm_policy_runtime;



GRANT UPDATE(authority) ON mdm_commands.operations TO mdm_policy_runtime;
GRANT UPDATE(revision) ON mdm_commands.operations TO mdm_policy_runtime;
GRANT UPDATE(request) ON mdm_commands.operations TO mdm_policy_runtime;
GRANT UPDATE(state) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(result) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(invocation) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(source_objects) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(software_effect) ON mdm_commands.action_runs TO mdm_policy_runtime;
GRANT UPDATE(input_revision) ON mdm_commands.policy_recovery TO mdm_policy_runtime;







GRANT USAGE ON SCHEMA mdm_commands TO mdm_policy_runtime;
GRANT SELECT ON mdm_commands.agent_admission TO mdm_policy_runtime;

GRANT UPDATE(access_binding) ON mdm_commands.action_runs TO mdm_policy_runtime;

-- Namespace access accompanies the already-declared foreign-reader capabilities.
GRANT USAGE ON SCHEMA mdm_commands TO mdm_inventory_runtime,mdm_scope_runtime,mdm_telemetry_runtime;



GRANT UPDATE(offer_after_at,offer_after_id) ON mdm_commands.agent_admission TO mdm_command_runtime;
ALTER TABLE mdm_commands.output_chunks ADD FOREIGN KEY(tenant_id,attempt) REFERENCES mdm_agent.task_attempts(tenant_id,id);
