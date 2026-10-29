-- Foreign references and precise consumers of Policy-owned facts.
BEGIN;
ALTER TABLE mdm_policy.assignments ADD FOREIGN KEY(tenant_id) REFERENCES public.mdm_tenants(tenant_id);
ALTER TABLE mdm_policy.assignments ADD FOREIGN KEY(tenant_id,scope_result) REFERENCES mdm_scope.scope_runs(tenant_id,id);
GRANT USAGE ON SCHEMA mdm_policy TO mdm_command_runtime;
GRANT EXECUTE ON FUNCTION mdm_policy.lock_policy(uuid) TO mdm_flow_runtime,mdm_command_runtime,mdm_access;
GRANT SELECT ON mdm_policy.policies,mdm_policy.versions,mdm_policy.triggers,mdm_policy.assignments TO mdm_command_runtime;
GRANT SELECT ON mdm_policy.policies,mdm_policy.versions TO mdm_access;
GRANT SELECT,INSERT ON mdm_policy.event_batches,mdm_policy.event_members,mdm_policy.work TO mdm_command_runtime;
GRANT UPDATE(decision) ON mdm_policy.event_members TO mdm_command_runtime;
GRANT UPDATE(completed,failure) ON mdm_policy.work TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_policy.assignments,mdm_policy.work TO mdm_flow_runtime;
GRANT UPDATE(input,availability,reason,target,scope_result,entry_revision) ON mdm_policy.assignments TO mdm_flow_runtime;
GRANT UPDATE(forwarded,completed,cursor,replacement_task,authority_revision,failure,failure_detail) ON mdm_policy.work TO mdm_flow_runtime;
COMMIT;
