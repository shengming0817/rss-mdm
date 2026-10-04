-- Quota configuration and organization responsibility are registration-owned.
BEGIN;
ALTER TABLE mdm_access.requests ADD COLUMN self_service boolean NOT NULL DEFAULT false;
CREATE TABLE mdm_access.registration_quota_settings (
    tenant_id uuid NOT NULL,
    subject text NOT NULL CHECK(length(subject) BETWEEN 1 AND 256),
    revision bigint NOT NULL CHECK(revision>0),
    agent bigint CHECK(agent BETWEEN 0 AND 4294967295),
    windows_mdm bigint CHECK(windows_mdm BETWEEN 0 AND 4294967295),
    macos_mdm bigint CHECK(macos_mdm BETWEEN 0 AND 4294967295),
    PRIMARY KEY(tenant_id,subject),
    CHECK(subject<>'tenant' OR (agent IS NOT NULL AND windows_mdm IS NOT NULL AND macos_mdm IS NOT NULL))
);
CREATE TABLE mdm_access.registration_users (
    tenant_id uuid NOT NULL,
    device text NOT NULL,
    revision bigint NOT NULL CHECK(revision>0),
    instance text,
    principal text,
    PRIMARY KEY(tenant_id,device),
    CHECK((instance IS NULL)=(principal IS NULL))
);
ALTER TABLE mdm_access.registration_quota_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.registration_quota_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.registration_quota_settings USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_access.registration_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.registration_users FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.registration_users USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.registration_quota_settings,mdm_access.registration_users TO mdm_access;
GRANT UPDATE(revision,agent,windows_mdm,macos_mdm) ON mdm_access.registration_quota_settings TO mdm_access;
GRANT UPDATE(revision,instance,principal) ON mdm_access.registration_users TO mdm_access;
COMMIT;
