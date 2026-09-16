BEGIN;
-- Owner-executed V1 schema. Runtime cannot alter identities or immutable records.
CREATE SCHEMA mdm_resource;
REVOKE ALL ON SCHEMA mdm_resource FROM PUBLIC;
CREATE TABLE mdm_resource.aggregates (
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128),
 revision bigint NOT NULL CHECK(revision>=0),
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 67108864), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_resource.immutable (
 tenant_id uuid NOT NULL, owner text NOT NULL CHECK(octet_length(owner)<=128),
 kind text NOT NULL CHECK(kind IN ('version')),
 key text NOT NULL CHECK(octet_length(key) BETWEEN 1 AND 512),
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 67108864), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,owner,kind,key)
);
CREATE TABLE mdm_resource.requests (
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128), owner text NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 67108864),
 receipt bytea NOT NULL CHECK(octet_length(receipt) BETWEEN 1 AND 67108864), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,owner) REFERENCES mdm_resource.aggregates(tenant_id,id)
);
ALTER TABLE mdm_resource.aggregates ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_resource.aggregates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_resource.aggregates USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_resource.aggregates FROM PUBLIC;
ALTER TABLE mdm_resource.immutable ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_resource.immutable FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_resource.immutable USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_resource.immutable FROM PUBLIC;
ALTER TABLE mdm_resource.requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_resource.requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_resource.requests USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_resource.requests FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_resource TO mdm_resource_runtime;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_resource TO mdm_resource_runtime;
GRANT UPDATE(revision,document,digest) ON mdm_resource.aggregates TO mdm_resource_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_resource_runtime;
GRANT SELECT ON rss_transactional_messaging.policy TO mdm_resource_runtime;
GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO mdm_resource_runtime;
GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO mdm_resource_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_resource_runtime;
COMMIT;
