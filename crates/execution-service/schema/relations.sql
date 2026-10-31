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

GRANT UPDATE(source_objects) ON TABLE mdm_commands.action_runs TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_commands.operations TO mdm_policy_runtime;

GRANT UPDATE(authority) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT UPDATE(revision,observed_command_version) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted,dispatch_failure) ON TABLE mdm_commands.operations TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.policy_recovery TO mdm_command_runtime;

GRANT UPDATE(recovery_after,input_revision,input_consumed,input_window) ON TABLE mdm_commands.policy_recovery TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_commands.requests TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_commands TO mdm_access;

GRANT SELECT ON TABLE mdm_commands.operations TO mdm_access;

GRANT SELECT ON mdm_commands.action_runs TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_commands.windows_pending_operations(uuid,bigint,uuid) TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_commands.windows_wake_candidates(uuid) TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_commands.retirement_commands(uuid,text),mdm_commands.save_retired_command(uuid,uuid,bigint,bigint) TO mdm_access,mdm_command_runtime;

GRANT EXECUTE ON FUNCTION mdm_commands.save_retired_action(uuid,uuid,jsonb,jsonb) TO mdm_access,mdm_command_runtime;

COMMIT;

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

GRANT UPDATE(source_objects) ON mdm_commands.action_runs TO mdm_policy_runtime;

GRANT UPDATE(input_revision) ON mdm_commands.policy_recovery TO mdm_policy_runtime;

GRANT USAGE ON SCHEMA mdm_commands TO mdm_policy_runtime;

GRANT SELECT ON mdm_commands.agent_admission TO mdm_policy_runtime;

GRANT UPDATE(access_binding) ON mdm_commands.action_runs TO mdm_policy_runtime;

-- Namespace access accompanies the already-declared foreign-reader capabilities.
GRANT USAGE ON SCHEMA mdm_commands TO mdm_inventory_runtime,mdm_scope_runtime,mdm_telemetry_runtime;
