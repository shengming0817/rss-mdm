BEGIN;
CREATE SCHEMA mdm_mail;
CREATE TABLE mdm_mail.heads(tenant_id uuid PRIMARY KEY,revision bigint NOT NULL CHECK(revision>=0),selected_revision bigint);
CREATE TABLE mdm_mail.versions(
 tenant_id uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),operation_id uuid NOT NULL,
 fingerprint_key text NOT NULL,fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 profile text NOT NULL CHECK(length(profile) BETWEEN 1 AND 128),sender text NOT NULL,recipient text NOT NULL,
 credentials bytea NOT NULL,endpoint_digest bytea,hostname text,address text,tls_mode text CHECK(tls_mode IN('implicit','starttls')),tls_roots bytea,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','submitting','accepted','failed','unknown')),
 attempted_at bigint,accepted_at bigint,failure_reason text CHECK(failure_reason IN('profile_unavailable','tls_or_authentication_failed','submission_unknown','rejected_by_server')),
 PRIMARY KEY(tenant_id,revision),UNIQUE(tenant_id,operation_id),FOREIGN KEY(tenant_id) REFERENCES mdm_mail.heads(tenant_id),
 CHECK((endpoint_digest IS NULL AND hostname IS NULL AND address IS NULL AND tls_mode IS NULL AND tls_roots IS NULL) OR (octet_length(endpoint_digest)=32 AND hostname IS NOT NULL AND address IS NOT NULL AND tls_mode IS NOT NULL AND tls_roots IS NOT NULL))
);
ALTER TABLE mdm_mail.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_mail.heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_mail.heads USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_mail.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_mail.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_mail.versions USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY insert_only ON mdm_mail.heads AS RESTRICTIVE FOR INSERT WITH CHECK(current_user::text='mdm_owner'::text OR (revision=0 AND selected_revision IS NULL));
CREATE POLICY insert_only ON mdm_mail.versions AS RESTRICTIVE FOR INSERT WITH CHECK(current_user::text='mdm_owner'::text OR (state='pending'::text AND endpoint_digest IS NULL AND hostname IS NULL AND address IS NULL AND tls_mode IS NULL AND tls_roots IS NULL AND attempted_at IS NULL AND accepted_at IS NULL AND failure_reason IS NULL));
REVOKE ALL ON SCHEMA mdm_mail FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mdm_mail FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_mail TO mdm_access;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_mail TO mdm_access;
GRANT UPDATE(revision) ON mdm_mail.heads TO mdm_access;
COMMIT;
