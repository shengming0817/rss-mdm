BEGIN;
-- Replace ephemeral protocol state. Historical identity, inventory and audit remain intact.
ALTER TABLE mdm_access.management_messages NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.management_sessions NO FORCE ROW LEVEL SECURITY;
DELETE FROM mdm_access.management_messages;
DELETE FROM mdm_access.management_sessions;
ALTER TABLE mdm_access.management_messages FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.management_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.management_sessions DROP CONSTRAINT management_sessions_state_check;
ALTER TABLE mdm_access.management_sessions ADD CONSTRAINT management_sessions_state_check CHECK(state IN ('challenge','collecting','complete','superseded'));
DROP INDEX mdm_access.one_advancing_management_session;
CREATE UNIQUE INDEX one_advancing_management_session ON mdm_access.management_sessions(tenant_id,registration) WHERE state IN ('challenge','collecting');
ALTER TABLE mdm_access.management_sessions ADD COLUMN run_id uuid;
GRANT UPDATE(run_id) ON mdm_access.management_sessions TO mdm_access;
-- Never reuse a Get CmdID within a source epoch, even when a retained SessionID is reused.
ALTER TABLE mdm_access.report_sources
 ADD COLUMN next_command bigint NOT NULL DEFAULT 1024 CHECK(next_command BETWEEN 1024 AND 4294967296),
 ADD COLUMN next_sequence bigint NOT NULL DEFAULT 0 CHECK(next_sequence>=0);
GRANT UPDATE(next_command,next_sequence) ON mdm_access.report_sources TO mdm_access;
CREATE TABLE mdm_access.collection_runs (
 tenant_id uuid NOT NULL, id uuid NOT NULL, registration uuid NOT NULL,
 source text NOT NULL CHECK(source='mdm.windows'), epoch uuid NOT NULL,
 scope text NOT NULL CHECK(octet_length(scope)<=4096), sequence bigint NOT NULL CHECK(sequence>=0),
 session_id text NOT NULL, request_message bigint NOT NULL CHECK(request_message BETWEEN 1 AND 8),
 first_command bigint NOT NULL CHECK(first_command BETWEEN 1024 AND 4294967294),
 request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 32768),
 started_at bigint NOT NULL CHECK(started_at>=0),
 attempts text NOT NULL CHECK(octet_length(attempts)<=8192),
 result text NOT NULL CHECK(result IN ('pending','snapshot','partial','failed')),
 reason text CHECK(reason IN ('complete','message_budget','timeout','superseded','revoked')),
 batch bytea CHECK(octet_length(batch) BETWEEN 1 AND 8192),
 digest text CHECK(digest ~ '^[0-9a-f]{64}$'), sealed_at bigint,
 delivery_pending boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,registration,source,epoch,sequence),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id),
 CHECK((result='pending')=(sealed_at IS NULL)),
 CHECK((sealed_at IS NULL)=(reason IS NULL)),
 CHECK((batch IS NULL)=(digest IS NULL)),
 CHECK(NOT delivery_pending OR batch IS NOT NULL),
 CHECK(batch IS NULL OR sealed_at IS NOT NULL)
);
CREATE INDEX collection_latest ON mdm_access.collection_runs(tenant_id,registration,source,epoch,sequence DESC);
CREATE INDEX collection_delivery ON mdm_access.collection_runs(tenant_id,registration,source,epoch,sequence) WHERE delivery_pending;
ALTER TABLE mdm_access.collection_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.collection_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.collection_runs USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.collection_runs TO mdm_access;
GRANT UPDATE(attempts,result,reason,batch,digest,sealed_at,delivery_pending) ON mdm_access.collection_runs TO mdm_access;
-- Sealed intake is the durable authorization evidence; delivery progress is its only mutable part.
CREATE FUNCTION mdm_access.immutable_collection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.sealed_at IS NOT NULL AND (to_jsonb(OLD)-'delivery_pending') IS DISTINCT FROM (to_jsonb(NEW)-'delivery_pending') THEN
  RAISE EXCEPTION 'sealed collection is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION mdm_access.immutable_collection() FROM PUBLIC;
CREATE TRIGGER immutable_collection BEFORE UPDATE ON mdm_access.collection_runs FOR EACH ROW EXECUTE FUNCTION mdm_access.immutable_collection();
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
 ('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
  'protected_request','registration_bind','credential_revoke','device_report',
  'enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','enrollment_read','registration_read',
  'windows_discovery','windows_policy','windows_management','collection_read','collection_finish'));
COMMIT;
