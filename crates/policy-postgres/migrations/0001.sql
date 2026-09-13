BEGIN;
-- Owner-executed V1 schema. Runtime cannot alter identities or immutable records.
CREATE SCHEMA mdm_policy;
REVOKE ALL ON SCHEMA mdm_policy FROM PUBLIC;
CREATE TABLE mdm_policy.aggregates (
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128),
 revision bigint NOT NULL CHECK(revision>=0),
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 67108864), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_policy.immutable (
 tenant_id uuid NOT NULL, owner text NOT NULL CHECK(octet_length(owner)<=128),
 kind text NOT NULL CHECK(kind IN ('version','payload','targets','plan')),
 key text NOT NULL CHECK(octet_length(key) BETWEEN 1 AND 512),
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 67108864), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,owner,kind,key)
);
CREATE TABLE mdm_policy.requests (
 tenant_id uuid NOT NULL, id text NOT NULL CHECK(octet_length(id) BETWEEN 1 AND 128), owner text NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 67108864),
 receipt bytea NOT NULL CHECK(octet_length(receipt) BETWEEN 1 AND 67108864), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,owner) REFERENCES mdm_policy.aggregates(tenant_id,id)
);
CREATE TABLE mdm_policy.facts (
 tenant_id uuid NOT NULL, owner text NOT NULL, key text NOT NULL CHECK(octet_length(key) BETWEEN 1 AND 512),
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 67108864), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,owner,key), FOREIGN KEY(tenant_id,owner) REFERENCES mdm_policy.aggregates(tenant_id,id)
);
ALTER TABLE mdm_policy.aggregates ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_policy.aggregates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_policy.aggregates USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_policy.aggregates FROM PUBLIC;
ALTER TABLE mdm_policy.immutable ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_policy.immutable FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_policy.immutable USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_policy.immutable FROM PUBLIC;
ALTER TABLE mdm_policy.requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_policy.requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_policy.requests USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_policy.requests FROM PUBLIC;
ALTER TABLE mdm_policy.facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_policy.facts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_policy.facts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_policy.facts FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_policy TO mdm_policy_runtime;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_policy TO mdm_policy_runtime;
GRANT UPDATE(revision,document,digest) ON mdm_policy.aggregates TO mdm_policy_runtime;
GRANT UPDATE(document,digest) ON mdm_policy.facts TO mdm_policy_runtime;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_policy_runtime;
GRANT SELECT ON rss_transactional_messaging.policy TO mdm_policy_runtime;
GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO mdm_policy_runtime;
GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO mdm_policy_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_policy_runtime;
COMMIT;
