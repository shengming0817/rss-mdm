BEGIN;
-- Native Agent registration rechecks only the frozen source read authority.

ALTER TABLE mdm_commands.scope_channel_results ADD FOREIGN KEY(tenant_id,run) REFERENCES mdm_scope.scope_runs(tenant_id,id);

GRANT SELECT,INSERT ON mdm_commands.scope_channel_results TO mdm_flow_runtime;

GRANT SELECT ON mdm_commands.scope_channel_results TO mdm_command_runtime;

GRANT UPDATE(matched,pending,target,entry_revision) ON mdm_commands.scope_channel_results TO mdm_flow_runtime;
COMMIT;
GRANT SELECT ON mdm_commands.scope_channel_results TO mdm_access;

ALTER TABLE mdm_commands.scope_projection_runs ADD FOREIGN KEY(tenant_id,id) REFERENCES mdm_scope.scope_runs(tenant_id,id);
