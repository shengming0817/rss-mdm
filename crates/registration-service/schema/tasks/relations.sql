BEGIN;
SET LOCAL check_function_bodies=false;

ALTER TABLE ONLY mdm_registration_tasks.operations ADD CONSTRAINT operations_tenant_id_device_fkey FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.command_authorities (tenant_id, device);


ALTER TABLE ONLY mdm_registration_tasks.requests ADD CONSTRAINT requests_tenant_id_operation_fkey FOREIGN KEY (tenant_id, operation) REFERENCES mdm_registration_tasks.operations (tenant_id, id);


GRANT SELECT,INSERT ON TABLE mdm_registration_tasks.operations TO mdm_command_runtime;


GRANT SELECT ON TABLE mdm_registration_tasks.operations TO mdm_policy_runtime;


GRANT UPDATE(authority) ON TABLE mdm_registration_tasks.operations TO mdm_command_runtime;


GRANT UPDATE(revision,observed_command_version) ON TABLE mdm_registration_tasks.operations TO mdm_command_runtime;


GRANT UPDATE(gateway_accepted,dispatch_failure) ON TABLE mdm_registration_tasks.operations TO mdm_command_runtime;


GRANT SELECT,INSERT ON TABLE mdm_registration_tasks.requests TO mdm_command_runtime;


GRANT SELECT ON TABLE mdm_registration_tasks.operations TO mdm_access;


GRANT EXECUTE ON FUNCTION mdm_registration_tasks.installation_status(uuid) TO mdm_access,mdm_command_runtime,mdm_policy_runtime;


GRANT EXECUTE ON FUNCTION mdm_registration_tasks.windows_pending_operations(uuid,uuid) TO mdm_access;


GRANT EXECUTE ON FUNCTION mdm_registration_tasks.windows_wake_candidates(uuid) TO mdm_access;


GRANT EXECUTE ON FUNCTION mdm_registration_tasks.retirement_commands(uuid,text),mdm_registration_tasks.save_retired_command(uuid,uuid,bigint,bigint) TO mdm_access,mdm_command_runtime,mdm_policy_runtime;


-- Explicit integration privileges owned by this capability.

-- Execution intent participation by the Policy transaction owner.
GRANT SELECT,INSERT ON mdm_registration_tasks.operations TO mdm_policy_runtime;


GRANT SELECT,INSERT ON mdm_registration_tasks.requests TO mdm_policy_runtime;


GRANT UPDATE(authority) ON mdm_registration_tasks.operations TO mdm_policy_runtime;


GRANT UPDATE(revision) ON mdm_registration_tasks.operations TO mdm_policy_runtime;


GRANT UPDATE(request) ON mdm_registration_tasks.operations TO mdm_policy_runtime;

GRANT UPDATE(request) ON mdm_registration_tasks.operations TO mdm_command_runtime;

GRANT SELECT ON mdm_registration_tasks.operations TO mdm_access;
-- Immutable request coordinates used by the tenant-scoped activity projection.
GRANT SELECT(tenant_id,actor,id,operation) ON mdm_registration_tasks.requests TO mdm_access;
COMMIT;