-- Current execution schema for self-service authorization and immutable attempt material.
BEGIN;
ALTER TABLE mdm_commands.action_runs
 ADD COLUMN software_effect jsonb CHECK (software_effect IS NULL OR (jsonb_typeof(software_effect)='object' AND octet_length(software_effect::text)<=4096)),
 ADD COLUMN invocation_archive jsonb CHECK (invocation_archive IS NULL OR octet_length(invocation_archive::text)<=196608);
ALTER TABLE mdm_commands.action_attempts
 ADD COLUMN execution_material jsonb CHECK (execution_material IS NULL OR (jsonb_typeof(execution_material)='object' AND octet_length(execution_material::text)<=6291456));
GRANT UPDATE(software_effect) ON mdm_commands.action_runs TO mdm_command_runtime;
GRANT UPDATE(execution_material) ON mdm_commands.action_attempts TO mdm_command_runtime;
CREATE INDEX action_software_effect ON mdm_commands.action_runs(tenant_id,device) WHERE software_effect IS NOT NULL;
COMMIT;
