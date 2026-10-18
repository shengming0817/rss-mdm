BEGIN;
CREATE SCHEMA mdm_apple_runtime;
CREATE TABLE mdm_apple_runtime.heads (
 tenant_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN ('apns','profile','managed_account')),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 desired_revision bigint CHECK(desired_revision>0 AND desired_revision<=revision),
 PRIMARY KEY(tenant_id,purpose)
);
CREATE TABLE mdm_apple_runtime.versions (
 tenant_id uuid NOT NULL,
 purpose text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 key_id uuid NOT NULL,
 public_digest text NOT NULL CHECK(public_digest ~ '^[0-9a-f]{64}$'),
 private_key bytea NOT NULL,
 csr text NOT NULL,
 certificate text,
 certificate_digest text CHECK(certificate_digest ~ '^[0-9a-f]{64}$'),
 topic text,
 expires_at bigint,
 revoked boolean NOT NULL DEFAULT false,
 selected boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,purpose,revision),
 FOREIGN KEY(tenant_id,purpose) REFERENCES mdm_apple_runtime.heads(tenant_id,purpose),
 CHECK((certificate IS NULL AND certificate_digest IS NULL AND expires_at IS NULL) OR (certificate IS NOT NULL AND certificate_digest IS NOT NULL AND expires_at>0))
);
CREATE TABLE mdm_apple_runtime.operations (
 tenant_id uuid NOT NULL,
 operation_id uuid NOT NULL,
 fingerprint_key text NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 receipt jsonb NOT NULL,
 PRIMARY KEY(tenant_id,operation_id)
);
ALTER TABLE mdm_apple_runtime.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple_runtime.heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple_runtime.heads USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_apple_runtime.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple_runtime.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple_runtime.versions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_apple_runtime.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_apple_runtime.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_apple_runtime.operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA mdm_apple_runtime FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_apple_runtime FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_apple_runtime TO mdm_access;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_apple_runtime TO mdm_access;
GRANT UPDATE(revision,desired_revision) ON mdm_apple_runtime.heads TO mdm_access;
GRANT UPDATE(revoked,private_key,selected) ON mdm_apple_runtime.versions TO mdm_access;
COMMIT;
