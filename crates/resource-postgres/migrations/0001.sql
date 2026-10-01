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
-- Derived artifact references are written atomically by the sole Resource owner.
CREATE TABLE mdm_resource.artifact_refs (
 tenant_id uuid NOT NULL, owner text NOT NULL, version text NOT NULL CHECK(octet_length(version) BETWEEN 1 AND 128),
 sha256 bytea NOT NULL CHECK(octet_length(sha256)=32), length bigint NOT NULL CHECK(length>0), archived boolean NOT NULL,
 PRIMARY KEY(tenant_id,owner,version,sha256,length), FOREIGN KEY(tenant_id,owner) REFERENCES mdm_resource.aggregates(tenant_id,id)
);
CREATE TABLE mdm_resource.field_refs (
 tenant_id uuid NOT NULL,owner text NOT NULL,version text NOT NULL,field text NOT NULL CHECK(length(field)<=128),archived boolean NOT NULL,
 PRIMARY KEY(tenant_id,owner,version,field),FOREIGN KEY(tenant_id,owner) REFERENCES mdm_resource.aggregates(tenant_id,id)
);
CREATE INDEX field_refs_live ON mdm_resource.field_refs(tenant_id,field) WHERE NOT archived;
ALTER TABLE mdm_resource.field_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_resource.field_refs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_resource.field_refs USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_resource.field_refs FROM PUBLIC;
CREATE INDEX artifact_refs_live ON mdm_resource.artifact_refs(tenant_id,sha256) WHERE NOT archived;
ALTER TABLE mdm_resource.artifact_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_resource.artifact_refs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_resource.artifact_refs USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_resource.artifact_refs FROM PUBLIC;
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
GRANT UPDATE(archived) ON mdm_resource.artifact_refs,mdm_resource.field_refs TO mdm_resource_runtime;
GRANT UPDATE(revision,document,digest) ON mdm_resource.aggregates TO mdm_resource_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_resource_runtime;
GRANT SELECT ON rss_transactional_messaging.policy TO mdm_resource_runtime;
GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO mdm_resource_runtime;
GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO mdm_resource_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_resource_runtime;
COMMIT;
