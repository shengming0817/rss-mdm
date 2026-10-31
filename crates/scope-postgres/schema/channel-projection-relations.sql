BEGIN;
-- Native Agent registration rechecks only the frozen source read authority.

ALTER TABLE mdm_scope.scope_channel_results ADD FOREIGN KEY(tenant_id,run) REFERENCES mdm_scope.scope_runs(tenant_id,id);

GRANT SELECT,INSERT ON mdm_scope.scope_channel_results TO mdm_scope_runtime;

GRANT SELECT ON mdm_scope.scope_channel_results TO mdm_command_runtime;

GRANT UPDATE(matched,pending,target,entry_revision) ON mdm_scope.scope_channel_results TO mdm_scope_runtime;
COMMIT;
GRANT SELECT ON mdm_scope.scope_channel_results TO mdm_access;

ALTER TABLE mdm_scope.scope_projection_runs ADD FOREIGN KEY(tenant_id,id) REFERENCES mdm_scope.scope_runs(tenant_id,id);

GRANT SELECT ON mdm_scope.scope_projection_runs, mdm_scope.scope_channel_results TO mdm_policy_runtime;
