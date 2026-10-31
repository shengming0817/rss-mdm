-- Protocol identity only; business state stays with its operation owner.
BEGIN;
CREATE TABLE mdm_windows.native_commands (
 tenant_id uuid NOT NULL,id uuid NOT NULL,
 command_id text GENERATED ALWAYS AS (id::text) STORED,
 registration uuid NOT NULL,registration_generation bigint NOT NULL CHECK(registration_generation>0),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,id,registration,registration_generation),
 FOREIGN KEY(tenant_id,command_id) REFERENCES rss_device_command.commands(tenant_id,command_id),
 FOREIGN KEY(tenant_id,registration,registration_generation) REFERENCES mdm_access.registrations(tenant_id,id,generation)
);
ALTER TABLE mdm_windows.native_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_windows.native_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_windows.native_commands USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_windows.native_commands TO mdm_command_runtime,mdm_policy_runtime;
GRANT SELECT ON mdm_windows.native_commands TO mdm_access;
COMMIT;
