-- Registration owns command scope and management-root fencing.
BEGIN;
CREATE TABLE mdm_access.command_authorities (
    tenant_id uuid NOT NULL,
    device text NOT NULL,
    command_device uuid NOT NULL,
    generation bigint NOT NULL,
    epoch bigint NOT NULL,
    registration uuid NOT NULL,
    registration_generation bigint NOT NULL,
    CONSTRAINT devices_epoch_check CHECK ((epoch > 0)),
    CONSTRAINT devices_generation_check CHECK ((generation > 0)),
    CONSTRAINT devices_registration_generation_check CHECK ((registration_generation > 0))
);

ALTER TABLE ONLY mdm_access.command_authorities FORCE ROW LEVEL SECURITY;

ALTER TABLE mdm_access.command_authorities ADD PRIMARY KEY(tenant_id,device);
ALTER TABLE mdm_access.command_authorities ADD UNIQUE(tenant_id,command_device);
ALTER TABLE mdm_access.command_authorities ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);
ALTER TABLE mdm_access.command_authorities ADD FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
ALTER TABLE mdm_access.command_authorities ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.command_authorities USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.command_authorities TO mdm_command_runtime,mdm_policy_runtime;
GRANT SELECT ON mdm_access.command_authorities TO mdm_access;
GRANT UPDATE(epoch,registration,registration_generation) ON mdm_access.command_authorities TO mdm_command_runtime,mdm_policy_runtime;

COMMIT;
