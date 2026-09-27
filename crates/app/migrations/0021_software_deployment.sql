BEGIN;
-- Fresh-install V3 Agent profile. No V1/V2 runtime admission or compatibility rows.
ALTER TABLE mdm_access.agent_bindings DROP CONSTRAINT agent_binding_profile;
ALTER TABLE mdm_access.agent_bindings ADD CONSTRAINT agent_binding_profile CHECK (
 wire_version=3 AND capabilities IN (
  '["inventory.basic.v3"]',
  '["inventory.basic.v3","task.execute.v3"]',
  '["inventory.basic.v3","software.execute.v3"]',
  '["inventory.basic.v3","task.execute.v3","software.execute.v3"]'
 )
);
ALTER TABLE mdm_access.agent_bindings
 ADD COLUMN platform text NOT NULL CHECK(platform IN ('windows','macos')),
 ADD COLUMN architecture text NOT NULL CHECK(architecture IN ('x86_64','aarch64'));
ALTER TABLE mdm_commands.action_receipts DROP CONSTRAINT action_receipts_response_check;
ALTER TABLE mdm_commands.action_receipts ADD CONSTRAINT action_receipts_response_check CHECK(octet_length(response::text)<=6291456);
ALTER TABLE mdm_commands.action_attempts DROP CONSTRAINT action_attempts_offer_check;
ALTER TABLE mdm_commands.action_attempts ADD CONSTRAINT action_attempts_offer_check CHECK(octet_length(offer::text)<=6291456);
ALTER TABLE mdm_commands.action_attempts DROP CONSTRAINT action_attempts_permit_check;
ALTER TABLE mdm_commands.action_attempts ADD CONSTRAINT action_attempts_permit_check CHECK(permit IS NULL OR octet_length(permit::text)<=6291456);
GRANT SELECT ON mdm_planning.scopes,mdm_planning.scope_results TO mdm_command_runtime;
GRANT USAGE ON SCHEMA mdm_software TO mdm_command_runtime;
GRANT SELECT ON mdm_software.sources,mdm_software.approvals,mdm_software.materials TO mdm_command_runtime;
COMMIT;
