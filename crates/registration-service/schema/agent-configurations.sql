-- Registration settings and reusable configuration authority. Existing identities are unchanged.
BEGIN;
CREATE TABLE mdm_access.agent_enrollment_settings (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096)
);
CREATE TABLE mdm_access.agent_configurations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, operation_id uuid NOT NULL,
 creator text NOT NULL, instance text NOT NULL,
 secret_digest text NOT NULL CHECK(secret_digest ~ '^[0-9a-f]{64}$'),
 signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9_-]{86}$'),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=16384),
 quantity bigint CHECK(quantity BETWEEN 1 AND 4294967295),
 state text NOT NULL CHECK(state IN('available','revoked')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+interval '365 days'),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,operation_id)
);
ALTER TABLE mdm_access.agent_grants ADD COLUMN configuration_id uuid;
ALTER TABLE mdm_access.agent_grants ADD COLUMN configuration_binding jsonb CHECK(octet_length(configuration_binding::text)<=32768);
ALTER TABLE mdm_access.agent_grants ADD CONSTRAINT configuration_authority
 CHECK((source='configuration' AND configuration_id IS NOT NULL AND configuration_binding IS NOT NULL AND spki IS NOT NULL) OR (source<>'configuration' AND configuration_id IS NULL AND configuration_binding IS NULL));
ALTER TABLE mdm_access.agent_grants ADD CONSTRAINT configuration_device_key UNIQUE(tenant_id,configuration_id,spki);
ALTER TABLE mdm_access.agent_grants ADD FOREIGN KEY(tenant_id,configuration_id) REFERENCES mdm_access.agent_configurations(tenant_id,id);
ALTER TABLE mdm_access.agent_grants DROP CONSTRAINT agent_grants_source_check;
ALTER TABLE mdm_access.agent_grants ADD CONSTRAINT agent_grants_source_check CHECK(source IN('download','browser','native','recovery','renewal','configuration'));
CREATE INDEX agent_configuration_usage ON mdm_access.agent_grants(tenant_id,configuration_id);
ALTER TABLE mdm_access.agent_enrollment_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_enrollment_settings FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_configurations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_enrollment_settings USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_access.agent_configurations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_enrollment_settings TO mdm_access;
GRANT SELECT ON mdm_access.agent_enrollment_settings TO mdm_command_runtime;
GRANT UPDATE(revision,document) ON mdm_access.agent_enrollment_settings TO mdm_access;
GRANT SELECT,INSERT ON mdm_access.agent_configurations TO mdm_access;
GRANT UPDATE(state) ON mdm_access.agent_configurations TO mdm_access;
COMMIT;
