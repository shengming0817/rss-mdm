BEGIN;
CREATE TABLE mdm_commands.action_polls (
 tenant_id uuid NOT NULL,
 registration uuid NOT NULL,
 cancellation_after uuid,
 PRIMARY KEY(tenant_id,registration),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
ALTER TABLE mdm_commands.action_polls ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_commands.action_polls FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_commands.action_polls
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_commands.action_polls TO mdm_command_runtime;
GRANT UPDATE(cancellation_after) ON mdm_commands.action_polls TO mdm_command_runtime;
COMMIT;
