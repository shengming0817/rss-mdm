-- Script tables participate in the initiating Command or Policy transaction.
BEGIN;
ALTER TABLE mdm_script.runs ADD FOREIGN KEY(tenant_id,policy_version) REFERENCES mdm_policy.versions(tenant_id,id);
ALTER TABLE mdm_script.runs ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);
ALTER TABLE mdm_script.agent_admission ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);
ALTER TABLE mdm_script.policy_recovery ADD FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id);
ALTER TABLE mdm_script.output_chunks ADD FOREIGN KEY (tenant_id, attempt) REFERENCES mdm_agent.task_attempts (tenant_id, id);
GRANT USAGE ON SCHEMA mdm_script TO mdm_command_runtime,mdm_policy_runtime,mdm_access;
GRANT SELECT,INSERT ON mdm_script.runs TO mdm_command_runtime,mdm_policy_runtime;
GRANT UPDATE(state,result,invocation,source_objects) ON mdm_script.runs TO mdm_command_runtime,mdm_policy_runtime;
GRANT UPDATE(gateway_accepted,dispatch_failure) ON mdm_script.runs TO mdm_command_runtime;
GRANT SELECT ON mdm_script.runs TO mdm_access;
GRANT SELECT,INSERT ON mdm_script.receipts,mdm_script.output_chunks,mdm_script.agent_admission TO mdm_command_runtime;
GRANT UPDATE(policy_after) ON mdm_script.agent_admission TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_script.policy_recovery TO mdm_command_runtime,mdm_policy_runtime;
GRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON mdm_script.policy_recovery TO mdm_command_runtime;
GRANT UPDATE(input_revision) ON mdm_script.policy_recovery TO mdm_policy_runtime;
COMMIT;
