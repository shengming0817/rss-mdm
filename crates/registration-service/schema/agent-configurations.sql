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
 document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),
 quantity bigint CHECK(quantity BETWEEN 1 AND 4294967295),
 state text NOT NULL CHECK(state IN('available','revoked')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+interval '365 days'),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,operation_id)
);

ALTER TABLE mdm_access.agent_grants ADD FOREIGN KEY(tenant_id,configuration_id) REFERENCES mdm_access.agent_configurations(tenant_id,id);

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
-- Configuration signing has an independent lifetime from task-signing keys.
CREATE TABLE mdm_access.agent_configuration_keys (
 tenant_id uuid PRIMARY KEY, key_id text NOT NULL UNIQUE,
 public_key text NOT NULL CHECK(public_key ~ '^[A-Za-z0-9_-]{43}$'),
 private_key bytea NOT NULL CHECK(octet_length(private_key) BETWEEN 1 AND 4096)
);
CREATE TABLE mdm_access.agent_connection_drafts (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),
 PRIMARY KEY(tenant_id,revision)
);
CREATE TABLE mdm_access.agent_connection_versions (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=65536),
 PRIMARY KEY(tenant_id,revision),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm_access.agent_connection_drafts(tenant_id,revision)
);
CREATE TABLE mdm_access.agent_connection_deployments (
 tenant_id uuid NOT NULL, origin text NOT NULL CHECK(octet_length(origin) BETWEEN 1 AND 2048),
 service_id uuid NOT NULL, host_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), configuration_revision bigint NOT NULL CHECK(configuration_revision>=0), observed_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,origin)
);
CREATE TABLE mdm_access.agent_connection_observations (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 operation_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096), received_at bigint NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,registration,generation,operation_id),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES mdm_access.registrations(tenant_id,id,generation),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm_access.agent_connection_versions(tenant_id,revision)
);
CREATE INDEX agent_connection_latest_observation ON mdm_access.agent_connection_observations(tenant_id,registration,generation,revision DESC,recorded_at DESC);
ALTER TABLE mdm_access.agent_configuration_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_configuration_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_configuration_keys USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_configuration_keys TO mdm_access;
GRANT SELECT(tenant_id,public_key) ON mdm_access.agent_configuration_keys TO mdm_command_runtime,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime;
ALTER TABLE mdm_access.agent_connection_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_connection_drafts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_connection_drafts USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_connection_drafts TO mdm_access;
ALTER TABLE mdm_access.agent_connection_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_connection_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_connection_versions USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_connection_versions TO mdm_access;
GRANT SELECT ON mdm_access.agent_connection_versions TO mdm_command_runtime,mdm_inventory_runtime,mdm_scope_runtime,mdm_policy_runtime,mdm_telemetry_runtime;
ALTER TABLE mdm_access.agent_connection_deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_connection_deployments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_connection_deployments USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT ON mdm_access.agent_connection_deployments TO mdm_access;
ALTER TABLE mdm_access.agent_connection_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_connection_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_connection_observations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_connection_observations TO mdm_access;
CREATE TABLE mdm_access.agent_connection_failures (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 operation_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4096),
 origin text NOT NULL CHECK(octet_length(origin) BETWEEN 1 AND 2048),
 received_at bigint NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,registration,generation,operation_id),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES mdm_access.registrations(tenant_id,id,generation),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm_access.agent_connection_versions(tenant_id,revision)
);
CREATE INDEX agent_connection_latest_failure ON mdm_access.agent_connection_failures(tenant_id,registration,generation,recorded_at DESC);
ALTER TABLE mdm_access.agent_connection_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_connection_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_connection_failures USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_connection_failures TO mdm_access;
COMMIT;
