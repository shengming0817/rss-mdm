-- Native consent and admission evidence. No access token storage.
BEGIN;
CREATE TABLE mdm_windows.entra_consents (
 tenant_id uuid NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 entra_tenant uuid NOT NULL,
 entra_user uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 expires_at timestamptz NOT NULL,
 request_id uuid,
 request_digest text CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 CHECK((request_id IS NULL)=(request_digest IS NULL)),
 PRIMARY KEY(tenant_id,digest),
 FOREIGN KEY(tenant_id,request_id) REFERENCES mdm_access.requests(tenant_id,id)
);
CREATE TABLE mdm_windows.entra_admissions (
 tenant_id uuid NOT NULL,
 request_id uuid NOT NULL,
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,request_id),
 FOREIGN KEY(tenant_id,request_id) REFERENCES mdm_access.requests(tenant_id,id)
);
ALTER TABLE mdm_windows.entra_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_windows.entra_admissions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_windows.entra_admissions USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_windows.entra_admissions TO mdm_access;
ALTER TABLE mdm_windows.entra_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_windows.entra_consents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_windows.entra_consents USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY expired_only ON mdm_windows.entra_consents AS RESTRICTIVE FOR DELETE USING(expires_at<clock_timestamp());
GRANT SELECT,INSERT ON mdm_windows.entra_consents TO mdm_access;
GRANT UPDATE(request_id,request_digest) ON mdm_windows.entra_consents TO mdm_access;
GRANT DELETE ON mdm_windows.entra_consents TO mdm_access;
COMMIT;
