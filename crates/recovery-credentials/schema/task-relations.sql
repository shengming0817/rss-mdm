BEGIN;
SET LOCAL check_function_bodies=false;

ALTER TABLE mdm_recovery_tasks.operations ADD FOREIGN KEY (tenant_id, device) REFERENCES mdm_access.command_authorities (tenant_id, device);

ALTER TABLE mdm_recovery_tasks.requests ADD FOREIGN KEY (tenant_id, operation) REFERENCES mdm_recovery_tasks.operations (tenant_id, id);

GRANT SELECT ON mdm_recovery_tasks.operations TO mdm_access;

GRANT SELECT,INSERT ON mdm_recovery_tasks.operations,mdm_recovery_tasks.requests TO mdm_command_runtime;

GRANT UPDATE(authority,revision,observed_command_version,gateway_accepted,dispatch_failure,request) ON mdm_recovery_tasks.operations TO mdm_command_runtime;

GRANT EXECUTE ON FUNCTION mdm_recovery_tasks.native_status(uuid),mdm_recovery_tasks.retirement_commands(uuid,text),mdm_recovery_tasks.save_retired_command(uuid,uuid,bigint,bigint) TO mdm_access,mdm_command_runtime,mdm_policy_runtime;
-- Immutable request coordinates used by the tenant-scoped activity projection.
GRANT SELECT(tenant_id,actor,id,operation) ON mdm_recovery_tasks.requests TO mdm_access;
COMMIT;
-- Previous configuration ownership requires only the authenticated original request.
GRANT USAGE ON SCHEMA mdm_recovery_tasks TO mdm_policy_runtime;
GRANT SELECT(tenant_id,id,device,request,input_context)
 ON mdm_recovery_tasks.operations TO mdm_policy_runtime;
