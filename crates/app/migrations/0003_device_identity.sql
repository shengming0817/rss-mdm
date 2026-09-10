BEGIN;
CREATE TABLE mdm_access.devices (
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(length(id) BETWEEN 1 AND 255),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_access.registrations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, device text NOT NULL,
 channel text NOT NULL CHECK(channel IN ('agent','mdm')),
 generation bigint NOT NULL CHECK(generation>0),
 request_id uuid NOT NULL, state text NOT NULL CHECK(state IN ('active','superseded','revoked')),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,request_id), UNIQUE(tenant_id,device,channel,generation), UNIQUE(tenant_id,id,channel),
 FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id),
 FOREIGN KEY(tenant_id,request_id) REFERENCES mdm_access.requests(tenant_id,id)
);
CREATE UNIQUE INDEX one_active_registration ON mdm_access.registrations(tenant_id,device,channel) WHERE state='active';
CREATE TABLE mdm_access.credentials (
 tenant_id uuid NOT NULL, id uuid NOT NULL, registration uuid NOT NULL,
 channel text NOT NULL CHECK(channel IN ('agent','mdm')),
 locator text NOT NULL CHECK(locator ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('active','superseded','revoked')),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,channel,locator), UNIQUE(tenant_id,registration),
 FOREIGN KEY(tenant_id,registration,channel) REFERENCES mdm_access.registrations(tenant_id,id,channel)
);
CREATE TABLE mdm_access.report_sources (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, source text NOT NULL CHECK(length(source) BETWEEN 1 AND 255),
 epoch uuid NOT NULL, coverage text NOT NULL, enabled boolean NOT NULL,
 PRIMARY KEY(tenant_id,registration,source),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['devices','registrations','credentials','report_sources'] LOOP
  EXECUTE format('ALTER TABLE mdm_access.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_access.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_access.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT ON mdm_access.requests TO mdm_access;
GRANT SELECT,INSERT ON mdm_access.devices,mdm_access.registrations,mdm_access.credentials,mdm_access.report_sources TO mdm_access;
GRANT UPDATE(state) ON mdm_access.registrations,mdm_access.credentials TO mdm_access;
GRANT UPDATE(enabled) ON mdm_access.report_sources TO mdm_access;
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN ('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication','protected_request','registration_bind','credential_revoke','device_report'));
ALTER TABLE mdm_access.audit ADD COLUMN registration_id uuid;
-- Attempted/unknown registrations may not commit; denial audit must still be writable.
COMMIT;
