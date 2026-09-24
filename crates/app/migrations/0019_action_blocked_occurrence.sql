BEGIN;
ALTER TABLE mdm_commands.action_plans
  ADD COLUMN blocked_at bigint CHECK(blocked_at>=0);
GRANT UPDATE(blocked_at) ON mdm_commands.action_plans TO mdm_command_runtime;
ALTER TABLE mdm_access.agent_bindings DROP CONSTRAINT agent_binding_profile;
ALTER TABLE mdm_access.agent_bindings ADD CONSTRAINT agent_binding_profile CHECK (
 (wire_version=1 AND capabilities='["inventory.basic.v1"]') OR
 (wire_version=2 AND capabilities IN (
   '["inventory.basic.v2"]',
   '["inventory.basic.v2","task.execute.v2"]'
 ))
);
COMMIT;
