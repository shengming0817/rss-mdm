BEGIN;
CREATE SCHEMA mdm_wns;
CREATE TABLE mdm_wns.heads (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>=0),
 desired_revision bigint CHECK(desired_revision>0 AND desired_revision<=revision)
);
CREATE TABLE mdm_wns.versions (
 tenant_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), operation_id uuid NOT NULL,
 actor text NOT NULL, fingerprint_key text NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 pfn text NOT NULL CHECK(length(pfn) BETWEEN 1 AND 256), sid_digest bytea NOT NULL CHECK(octet_length(sid_digest)=32),
 configuration bytea NOT NULL CHECK(octet_length(configuration)=32), material bytea NOT NULL,
 attempted_at bigint, failure_reason text CHECK(failure_reason IN ('oauth_validation_failed')),
 qualified_at bigint, selected boolean NOT NULL DEFAULT false, revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,revision), UNIQUE(tenant_id,operation_id),
 FOREIGN KEY(tenant_id) REFERENCES mdm_wns.heads(tenant_id)
);
CREATE TABLE mdm_wns.revocations (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, revision bigint NOT NULL,
 material_revision bigint NOT NULL, fingerprint_key text NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(tenant_id,operation_id), FOREIGN KEY(tenant_id,material_revision) REFERENCES mdm_wns.versions(tenant_id,revision)
);
ALTER TABLE mdm_wns.revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_wns.revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_wns.revocations USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_wns.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_wns.heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_wns.heads USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_wns.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_wns.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_wns.versions USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY insert_only ON mdm_wns.heads AS RESTRICTIVE FOR INSERT WITH CHECK(current_user::text='mdm_owner'::text OR (revision=0 AND desired_revision IS NULL));
CREATE POLICY insert_only ON mdm_wns.versions AS RESTRICTIVE FOR INSERT WITH CHECK(current_user::text='mdm_owner'::text OR (qualified_at IS NULL AND attempted_at IS NULL AND failure_reason IS NULL AND NOT selected AND NOT revoked));
REVOKE ALL ON SCHEMA mdm_wns FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_wns FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_wns TO mdm_access;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_wns TO mdm_access;
GRANT UPDATE(revision) ON mdm_wns.heads TO mdm_access;
GRANT UPDATE(revoked) ON mdm_wns.versions TO mdm_access;
-- 资格核验和切换仅由受限部署进程完成；普通 HTTP 只保留候选请求。
COMMIT;
