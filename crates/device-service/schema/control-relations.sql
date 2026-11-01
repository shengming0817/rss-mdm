-- Fresh installation: Device owns fixed controls and accepted unmanage work.
BEGIN;

SET LOCAL check_function_bodies = false;

ALTER TABLE ONLY mdm_devices.unmanage_runs
    ADD CONSTRAINT unmanage_runs_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.devices(tenant_id, id);

ALTER TABLE ONLY mdm_devices.unmanage_runs
    ADD CONSTRAINT unmanage_runs_tenant_id_policy_version_fkey FOREIGN KEY (tenant_id, policy_version) REFERENCES mdm_policy.versions(tenant_id, id);

ALTER TABLE ONLY mdm_devices.unmanage_runs
    ADD CONSTRAINT unmanage_runs_tenant_id_registration_fkey FOREIGN KEY (tenant_id, registration) REFERENCES mdm_access.registrations(tenant_id, id);

ALTER TABLE ONLY mdm_devices.control_operations
    ADD CONSTRAINT control_operations_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.command_authorities(tenant_id, device);

ALTER TABLE ONLY mdm_devices.control_operations
    ADD CONSTRAINT control_operations_tenant_id_policy_version_fkey FOREIGN KEY (tenant_id, policy_version) REFERENCES mdm_policy.versions(tenant_id, id);

ALTER TABLE ONLY mdm_devices.unmanage_policy_recovery
    ADD CONSTRAINT unmanage_policy_recovery_tenant_id_policy_fkey FOREIGN KEY (tenant_id, policy) REFERENCES mdm_policy.policies(tenant_id, id);

ALTER TABLE ONLY mdm_devices.control_requests
    ADD CONSTRAINT control_requests_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_devices.control_operations(tenant_id, id);

GRANT USAGE ON SCHEMA mdm_devices TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_devices TO mdm_policy_runtime;

GRANT SELECT,INSERT ON TABLE mdm_devices.unmanage_receipts TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_devices.unmanage_runs TO mdm_command_runtime;

GRANT UPDATE(state) ON TABLE mdm_devices.unmanage_runs TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted) ON TABLE mdm_devices.unmanage_runs TO mdm_command_runtime;

GRANT UPDATE(result) ON TABLE mdm_devices.unmanage_runs TO mdm_command_runtime;

GRANT UPDATE(source_objects) ON TABLE mdm_devices.unmanage_runs TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_devices.control_operations TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_devices.control_operations TO mdm_policy_runtime;

GRANT UPDATE(authority) ON TABLE mdm_devices.control_operations TO mdm_command_runtime;

GRANT UPDATE(revision,observed_command_version) ON TABLE mdm_devices.control_operations TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted,dispatch_failure) ON TABLE mdm_devices.control_operations TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_devices.unmanage_policy_recovery TO mdm_command_runtime;

GRANT UPDATE(recovery_after,input_revision,input_consumed,input_window) ON TABLE mdm_devices.unmanage_policy_recovery TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_devices.control_requests TO mdm_command_runtime;

GRANT USAGE ON SCHEMA mdm_devices TO mdm_access;

GRANT SELECT ON TABLE mdm_devices.control_operations TO mdm_access;

GRANT SELECT ON mdm_devices.unmanage_runs TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_devices.windows_pending_operations(uuid,bigint,uuid) TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_devices.windows_wake_candidates(uuid) TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_devices.retirement_commands(uuid,text),mdm_devices.save_retired_command(uuid,uuid,bigint,bigint) TO mdm_access,mdm_command_runtime;

GRANT EXECUTE ON FUNCTION mdm_devices.save_retired_action(uuid,uuid,jsonb,jsonb) TO mdm_access,mdm_command_runtime;

COMMIT;

GRANT SELECT ON mdm_policy.policies,mdm_policy.versions TO mdm_access;

-- Policy authors may announce changed desired work, never consume or complete it.
GRANT SELECT(tenant_id,policy,input_revision),INSERT(tenant_id,policy,input_revision),UPDATE(input_revision) ON mdm_devices.unmanage_policy_recovery TO mdm_policy_runtime;

-- Explicit integration privileges owned by this capability.

-- Execution intent participation by the Policy transaction owner.
GRANT SELECT,INSERT ON mdm_devices.control_operations TO mdm_policy_runtime;

GRANT SELECT,INSERT ON mdm_devices.control_requests TO mdm_policy_runtime;

GRANT SELECT,INSERT ON mdm_devices.unmanage_runs TO mdm_policy_runtime;

GRANT SELECT,INSERT ON mdm_devices.unmanage_receipts TO mdm_policy_runtime;

GRANT SELECT,INSERT ON mdm_devices.unmanage_policy_recovery TO mdm_policy_runtime;

GRANT UPDATE(authority) ON mdm_devices.control_operations TO mdm_policy_runtime;

GRANT UPDATE(revision) ON mdm_devices.control_operations TO mdm_policy_runtime;

GRANT UPDATE(request) ON mdm_devices.control_operations TO mdm_policy_runtime;

GRANT UPDATE(state) ON mdm_devices.unmanage_runs TO mdm_policy_runtime;

GRANT UPDATE(result) ON mdm_devices.unmanage_runs TO mdm_policy_runtime;

GRANT UPDATE(source_objects) ON mdm_devices.unmanage_runs TO mdm_policy_runtime;

GRANT UPDATE(input_revision) ON mdm_devices.unmanage_policy_recovery TO mdm_policy_runtime;

GRANT USAGE ON SCHEMA mdm_devices TO mdm_policy_runtime;

-- Namespace access accompanies the already-declared foreign-reader capabilities.
GRANT USAGE ON SCHEMA mdm_devices TO mdm_inventory_runtime,mdm_scope_runtime,mdm_telemetry_runtime;
