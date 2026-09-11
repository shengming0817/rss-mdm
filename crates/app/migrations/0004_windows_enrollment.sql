BEGIN;
-- Existing identity, operation and audit facts remain. Retired requests never gain a password.
-- The installer owns these tables; temporarily lift FORCE only inside this migration transaction.
ALTER TABLE mdm_access.grants NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.requests NO FORCE ROW LEVEL SECURITY;
UPDATE mdm_access.grants SET state='revoked' WHERE state='available';
ALTER TABLE mdm_access.requests
 ADD COLUMN state text NOT NULL DEFAULT 'cancelled' CHECK(state IN ('pending','bound','cancelled')),
 ADD COLUMN expected_generation bigint CHECK(expected_generation>=0),
 ADD COLUMN password_digest text CHECK(password_digest ~ '^[0-9a-f]{64}$'),
 ADD COLUMN password_version bigint NOT NULL DEFAULT 0 CHECK(password_version>=0),
 ADD COLUMN session_ref uuid,
 ADD COLUMN expires_at timestamptz,
 ADD COLUMN issuance_operation uuid,
 ADD CONSTRAINT enrollment_shape CHECK(state='cancelled' OR
   (expected_generation IS NOT NULL AND password_digest IS NOT NULL AND password_version>0
    AND session_ref IS NOT NULL AND expires_at IS NOT NULL AND issuance_operation IS NOT NULL)),
 ADD CONSTRAINT enrollment_issuance_operation UNIQUE(tenant_id,issuance_operation);
ALTER TABLE mdm_access.grants FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.requests FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_access.enrollment_intents (
 tenant_id uuid NOT NULL, request_id uuid NOT NULL,
 enrollment_type text NOT NULL CHECK(enrollment_type IN ('Full','Device')),
 csr bytea NOT NULL CHECK(octet_length(csr) BETWEEN 1 AND 32768),
 tbs bytea NOT NULL CHECK(octet_length(tbs) BETWEEN 1 AND 32768),
 issuer bytea NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 32768),
 configuration text NOT NULL CHECK(configuration ~ '^[0-9a-f]{64}$'),
 registration uuid NOT NULL, credential uuid NOT NULL, epoch uuid NOT NULL,
 secrets bytea NOT NULL CHECK(octet_length(secrets) BETWEEN 28 AND 4096),
 PRIMARY KEY(tenant_id,request_id),
 FOREIGN KEY(tenant_id,request_id) REFERENCES mdm_access.requests(tenant_id,id)
);
CREATE TABLE mdm_access.enrollment_certificates (
 tenant_id uuid NOT NULL, request_id uuid NOT NULL,
 certificate bytea NOT NULL CHECK(octet_length(certificate) BETWEEN 1 AND 32768),
 server_nonce bytea NOT NULL CHECK(octet_length(server_nonce) BETWEEN 16 AND 64),
 PRIMARY KEY(tenant_id,request_id),
 FOREIGN KEY(tenant_id,request_id) REFERENCES mdm_access.enrollment_intents(tenant_id,request_id)
);
CREATE TABLE mdm_access.management_sessions (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, session_id text NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
 generation bigint NOT NULL, credential uuid NOT NULL,
 state text NOT NULL CHECK(state IN ('challenge','complete','superseded')),
 last_message bigint NOT NULL CHECK(last_message>0),
 client_authenticated boolean NOT NULL,
 correlation text NOT NULL CHECK(octet_length(correlation)<=32768),
 nonce bytea NOT NULL CHECK(octet_length(nonce) BETWEEN 16 AND 64),
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,registration,session_id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id),
 FOREIGN KEY(tenant_id,credential) REFERENCES mdm_access.credentials(tenant_id,id)
);
CREATE UNIQUE INDEX one_advancing_management_session ON mdm_access.management_sessions(tenant_id,registration) WHERE state='challenge';
CREATE TABLE mdm_access.management_messages (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, session_id text NOT NULL, message_id bigint NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 response bytea NOT NULL CHECK(octet_length(response) BETWEEN 1 AND 262144),
 PRIMARY KEY(tenant_id,registration,session_id,message_id),
 FOREIGN KEY(tenant_id,registration,session_id) REFERENCES mdm_access.management_sessions(tenant_id,registration,session_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['enrollment_intents','enrollment_certificates','management_sessions','management_messages'] LOOP
  EXECUTE format('ALTER TABLE mdm_access.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_access.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_access.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_access.%I TO mdm_access',t);
 END LOOP;
END $$;
REVOKE UPDATE(state) ON mdm_access.grants FROM mdm_access;
GRANT UPDATE(state,password_digest,password_version,session_ref,expires_at) ON mdm_access.requests TO mdm_access;
GRANT UPDATE(server_nonce) ON mdm_access.enrollment_certificates TO mdm_access;
GRANT UPDATE(state,last_message,correlation,nonce,client_authenticated) ON mdm_access.management_sessions TO mdm_access;
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
-- Retain historical action vocabulary for immutable audit facts only.
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
 ('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
  'protected_request','registration_bind','credential_revoke','device_report',
  'enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','windows_discovery','windows_policy','windows_management'));
COMMIT;
