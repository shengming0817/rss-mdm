-- Registration admission is independent of device management lifecycle.
BEGIN;
CREATE TABLE mdm_access.registration_admission (
 tenant_id uuid NOT NULL,
 channel text NOT NULL CHECK(channel IN ('agent','windows_mdm','macos_mdm')),
 revision bigint NOT NULL CHECK(revision>0),
 paused boolean NOT NULL,
 PRIMARY KEY(tenant_id,channel)
);
ALTER TABLE mdm_access.registration_admission ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.registration_admission FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.registration_admission USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.registration_admission TO mdm_access;
GRANT UPDATE(revision,paused) ON mdm_access.registration_admission TO mdm_access;
GRANT SELECT ON mdm_access.registration_admission TO mdm_command_runtime;
COMMIT;
