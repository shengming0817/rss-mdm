-- Fresh installation: execution owns these objects.
BEGIN;

SET LOCAL check_function_bodies = false;

ALTER TABLE ONLY mdm_software_deployment.agent_admission ADD CONSTRAINT agent_admission_tenant_id_registration_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices (tenant_id, id);

ALTER TABLE ONLY mdm_software_deployment.action_runs
    ADD CONSTRAINT action_runs_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices(tenant_id, id);

ALTER TABLE ONLY mdm_software_deployment.action_runs
    ADD CONSTRAINT action_runs_tenant_id_policy_version_fkey FOREIGN KEY (tenant_id, policy_version) REFERENCES mdm_policy.versions(tenant_id, id);

ALTER TABLE ONLY mdm_software_deployment.action_runs ADD CONSTRAINT action_runs_tenant_id_registration_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices (tenant_id, id);

ALTER TABLE ONLY mdm_software_deployment.operations ADD CONSTRAINT operations_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.command_authorities (tenant_id, device);

ALTER TABLE ONLY mdm_software_deployment.operations
    ADD CONSTRAINT operations_tenant_id_policy_version_fkey FOREIGN KEY (tenant_id, policy_version) REFERENCES mdm_policy.versions(tenant_id, id);

ALTER TABLE ONLY mdm_software_deployment.policy_recovery
    ADD CONSTRAINT policy_recovery_tenant_id_policy_fkey FOREIGN KEY (tenant_id, policy) REFERENCES mdm_policy.policies(tenant_id, id);

ALTER TABLE ONLY mdm_software_deployment.requests ADD CONSTRAINT requests_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_software_deployment.operations (tenant_id, id);

GRANT USAGE ON SCHEMA mdm_software_deployment TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_software_deployment TO mdm_policy_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_deployment.agent_admission TO mdm_command_runtime;

GRANT UPDATE(policy_after) ON TABLE mdm_software_deployment.agent_admission TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_deployment.action_receipts TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_deployment.action_runs TO mdm_command_runtime;

GRANT UPDATE(state) ON TABLE mdm_software_deployment.action_runs TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted) ON TABLE mdm_software_deployment.action_runs TO mdm_command_runtime;

GRANT UPDATE(result) ON TABLE mdm_software_deployment.action_runs TO mdm_command_runtime;

GRANT UPDATE(invocation,source_objects) ON TABLE mdm_software_deployment.action_runs TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_deployment.operations TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_software_deployment.operations TO mdm_policy_runtime;

GRANT UPDATE(authority) ON TABLE mdm_software_deployment.operations TO mdm_command_runtime;

GRANT UPDATE(revision,observed_command_version) ON TABLE mdm_software_deployment.operations TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted,dispatch_failure) ON TABLE mdm_software_deployment.operations TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_deployment.policy_recovery TO mdm_command_runtime;

GRANT UPDATE(recovery_after,input_revision,input_consumed,input_window,dispatch_revision,dispatch_consumed,dispatch_window,dispatch_after) ON TABLE mdm_software_deployment.policy_recovery TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_software_deployment.requests TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_software_deployment TO mdm_access;

GRANT SELECT ON TABLE mdm_software_deployment.operations TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_software_deployment.installation_status(uuid) TO mdm_access,mdm_command_runtime,mdm_policy_runtime;

GRANT SELECT ON mdm_software_deployment.action_runs TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_software_deployment.windows_pending_operations(uuid,uuid) TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_software_deployment.windows_wake_candidates(uuid) TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_software_deployment.retirement_commands(uuid,text),mdm_software_deployment.save_retired_command(uuid,uuid,bigint,bigint) TO mdm_access,mdm_command_runtime;

GRANT EXECUTE ON FUNCTION mdm_software_deployment.save_retired_action(uuid,uuid,jsonb,jsonb) TO mdm_access,mdm_command_runtime;

GRANT UPDATE(software_effect) ON mdm_software_deployment.action_runs TO mdm_command_runtime;

-- Immutable request coordinates used by the tenant-scoped activity projection.
GRANT SELECT(tenant_id,actor,id,operation) ON mdm_software_deployment.requests TO mdm_access;
COMMIT;

ALTER TABLE mdm_software_deployment.software_stage_stats ADD FOREIGN KEY(tenant_id,version) REFERENCES mdm_policy.versions(tenant_id,id);

GRANT SELECT,INSERT ON mdm_software_deployment.software_stage_stats TO mdm_command_runtime;

GRANT UPDATE(gate_open,input,cursor,ready,counts,generation,membership_complete) ON mdm_software_deployment.software_stage_stats TO mdm_command_runtime;

GRANT SELECT ON mdm_software_deployment.software_binding_revisions TO mdm_command_runtime;

CREATE TRIGGER software_bindings AFTER INSERT OR UPDATE OR DELETE ON mdm_agent.bindings FOR EACH ROW EXECUTE FUNCTION mdm_software_deployment.advance_software_bindings();

ALTER TABLE mdm_software_deployment.software_stats_members ADD FOREIGN KEY(tenant_id,version,stage) REFERENCES mdm_software_deployment.software_stage_stats(tenant_id,version,stage);

ALTER TABLE mdm_software_deployment.software_result_changes ADD FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id);

GRANT SELECT,INSERT ON mdm_software_deployment.software_stats_members TO mdm_command_runtime;

GRANT UPDATE(generation,target,counts,waiting_until) ON mdm_software_deployment.software_stats_members TO mdm_command_runtime;

GRANT SELECT ON mdm_software_deployment.software_result_changes,mdm_software_deployment.software_binding_changes TO mdm_command_runtime;

GRANT SELECT ON mdm_policy.policies,mdm_policy.versions TO mdm_access;

-- Policy authors may announce changed desired work, never consume or complete it.
GRANT SELECT(tenant_id,policy,input_revision),INSERT(tenant_id,policy,input_revision),UPDATE(input_revision) ON mdm_software_deployment.policy_recovery TO mdm_policy_runtime;

-- Explicit integration privileges owned by this capability.

-- Execution intent participation by the Policy transaction owner.
GRANT SELECT,INSERT ON mdm_software_deployment.operations TO mdm_policy_runtime;

GRANT SELECT,INSERT ON mdm_software_deployment.requests TO mdm_policy_runtime;

GRANT SELECT,INSERT ON mdm_software_deployment.action_runs TO mdm_policy_runtime;

GRANT SELECT,INSERT ON mdm_software_deployment.action_receipts TO mdm_policy_runtime;

GRANT SELECT,INSERT ON mdm_software_deployment.policy_recovery TO mdm_policy_runtime;

GRANT UPDATE(authority) ON mdm_software_deployment.operations TO mdm_policy_runtime;

GRANT UPDATE(revision) ON mdm_software_deployment.operations TO mdm_policy_runtime;

GRANT UPDATE(request) ON mdm_software_deployment.operations TO mdm_policy_runtime;

GRANT UPDATE(state) ON mdm_software_deployment.action_runs TO mdm_policy_runtime;

GRANT UPDATE(result) ON mdm_software_deployment.action_runs TO mdm_policy_runtime;

GRANT UPDATE(invocation) ON mdm_software_deployment.action_runs TO mdm_policy_runtime;

GRANT UPDATE(source_objects) ON mdm_software_deployment.action_runs TO mdm_policy_runtime;

GRANT UPDATE(software_effect) ON mdm_software_deployment.action_runs TO mdm_policy_runtime;

GRANT UPDATE(input_revision) ON mdm_software_deployment.policy_recovery TO mdm_policy_runtime;

GRANT USAGE ON SCHEMA mdm_software_deployment TO mdm_policy_runtime;

GRANT SELECT ON mdm_software_deployment.agent_admission TO mdm_policy_runtime;

-- Namespace access accompanies the already-declared foreign-reader capabilities.
GRANT USAGE ON SCHEMA mdm_software_deployment TO mdm_inventory_runtime,mdm_scope_runtime,mdm_telemetry_runtime;