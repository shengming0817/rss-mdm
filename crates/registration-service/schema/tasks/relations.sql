-- Script tables participate in the initiating Command or Policy transaction.
BEGIN;

ALTER TABLE mdm_registration_tasks.runs ADD FOREIGN KEY(tenant_id,policy_version) REFERENCES mdm_policy.versions(tenant_id,id);

ALTER TABLE mdm_registration_tasks.runs ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);

ALTER TABLE mdm_registration_tasks.runs ADD FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);

ALTER TABLE mdm_registration_tasks.agent_admission ADD FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);

ALTER TABLE mdm_registration_tasks.policy_recovery ADD FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id);

GRANT USAGE ON SCHEMA mdm_registration_tasks TO mdm_command_runtime,mdm_policy_runtime,mdm_access;

GRANT SELECT,INSERT ON mdm_registration_tasks.runs TO mdm_command_runtime,mdm_policy_runtime;

GRANT UPDATE(state,result,invocation,source_objects) ON mdm_registration_tasks.runs TO mdm_command_runtime,mdm_policy_runtime;

GRANT UPDATE(gateway_accepted,dispatch_failure) ON mdm_registration_tasks.runs TO mdm_command_runtime;

GRANT SELECT ON mdm_registration_tasks.runs TO mdm_access;

GRANT UPDATE(policy_after) ON mdm_registration_tasks.agent_admission TO mdm_command_runtime;

GRANT SELECT,INSERT ON mdm_registration_tasks.policy_recovery TO mdm_command_runtime,mdm_policy_runtime;

GRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON mdm_registration_tasks.policy_recovery TO mdm_command_runtime;

GRANT UPDATE(input_revision) ON mdm_registration_tasks.policy_recovery TO mdm_policy_runtime;

COMMIT;
ALTER TABLE ONLY mdm_registration_tasks.operations
    ADD CONSTRAINT operations_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.command_authorities(tenant_id, device);

ALTER TABLE ONLY mdm_registration_tasks.requests
    ADD CONSTRAINT requests_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_registration_tasks.operations(tenant_id, id);

GRANT SELECT,INSERT ON TABLE mdm_registration_tasks.operations TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_registration_tasks.operations TO mdm_policy_runtime;

GRANT UPDATE(authority) ON TABLE mdm_registration_tasks.operations TO mdm_command_runtime;

GRANT UPDATE(revision,observed_command_version) ON TABLE mdm_registration_tasks.operations TO mdm_command_runtime;

GRANT UPDATE(gateway_accepted,dispatch_failure) ON TABLE mdm_registration_tasks.operations TO mdm_command_runtime;

GRANT SELECT,INSERT ON TABLE mdm_registration_tasks.requests TO mdm_command_runtime;

GRANT SELECT ON TABLE mdm_registration_tasks.operations TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_registration_tasks.installation_status(uuid) TO mdm_access,mdm_command_runtime,mdm_policy_runtime;

GRANT EXECUTE ON FUNCTION mdm_registration_tasks.windows_pending_operations(uuid,bigint,uuid) TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_registration_tasks.windows_wake_candidates(uuid) TO mdm_access;

GRANT EXECUTE ON FUNCTION mdm_registration_tasks.retirement_commands(uuid,text),mdm_registration_tasks.save_retired_command(uuid,uuid,bigint,bigint) TO mdm_access,mdm_command_runtime,mdm_policy_runtime;

-- Explicit integration privileges owned by this capability.

-- Execution intent participation by the Policy transaction owner.
GRANT SELECT,INSERT ON mdm_registration_tasks.operations TO mdm_policy_runtime;

GRANT SELECT,INSERT ON mdm_registration_tasks.requests TO mdm_policy_runtime;

GRANT UPDATE(authority) ON mdm_registration_tasks.operations TO mdm_policy_runtime;

GRANT UPDATE(revision) ON mdm_registration_tasks.operations TO mdm_policy_runtime;

GRANT UPDATE(request) ON mdm_registration_tasks.operations TO mdm_policy_runtime;
GRANT SELECT,INSERT ON mdm_registration_tasks.receipts,mdm_registration_tasks.agent_admission TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_registration_tasks.receipts TO mdm_policy_runtime;
GRANT SELECT ON mdm_registration_tasks.agent_admission TO mdm_policy_runtime;
GRANT UPDATE(request) ON mdm_registration_tasks.operations TO mdm_command_runtime;
GRANT SELECT ON mdm_registration_tasks.operations TO mdm_access;
