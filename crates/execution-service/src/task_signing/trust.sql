BEGIN;
CREATE SCHEMA mdm_task_signing;
CREATE TABLE mdm_task_signing.heads (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>=0)
);
CREATE TABLE mdm_task_signing.keys (
 tenant_id uuid NOT NULL, key_id text NOT NULL, private_key bytea NOT NULL,
 PRIMARY KEY(tenant_id,key_id)
);
CREATE TABLE mdm_task_signing.versions (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 operation_id uuid NOT NULL, fingerprint_key text NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,revision), UNIQUE(tenant_id,operation_id)
);
CREATE TABLE mdm_task_signing.acknowledgements (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, registration uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0), revision bigint NOT NULL CHECK(revision>0),
 digest text NOT NULL, PRIMARY KEY(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm_task_signing.versions(tenant_id,revision)
);
ALTER TABLE mdm_task_signing.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_task_signing.heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_task_signing.heads USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_task_signing.keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_task_signing.keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_task_signing.keys USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_task_signing.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_task_signing.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_task_signing.versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_task_signing.acknowledgements ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_task_signing.acknowledgements FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_task_signing.acknowledgements USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA mdm_task_signing FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_task_signing FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_task_signing TO mdm_access,mdm_command_runtime;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_task_signing TO mdm_access;
GRANT UPDATE(revision) ON mdm_task_signing.heads TO mdm_access;
GRANT UPDATE(private_key) ON mdm_task_signing.keys TO mdm_access;
GRANT SELECT ON mdm_task_signing.heads,mdm_task_signing.versions,mdm_task_signing.acknowledgements TO mdm_command_runtime;
COMMIT;
