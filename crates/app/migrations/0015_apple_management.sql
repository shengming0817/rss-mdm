-- Product Apple native management and the single successor control plane.
BEGIN;
ALTER TABLE mdm_access.requests ADD COLUMN source text;
-- This migration predates Apple admission: every historical mdm grant is Windows.
DO $$ DECLARE t text; BEGIN
 FOR t IN SELECT jsonb_array_elements_text(configuration->'tenants') FROM public.mdm_installation LOOP
  PERFORM set_config('rss.tenant_id',t,true);
  UPDATE mdm_access.requests SET source=CASE channel WHEN 'agent' THEN 'agent.builtin' WHEN 'mdm' THEN 'mdm.windows' END;
 END LOOP;
END $$;
ALTER TABLE mdm_access.requests ALTER COLUMN source SET NOT NULL;
ALTER TABLE mdm_access.requests ADD CONSTRAINT requests_source_check CHECK(source IN ('agent.builtin','mdm.windows','mdm.apple'));
ALTER TABLE mdm_access.requests DROP COLUMN channel;


ALTER TABLE mdm_access.collection_runs ADD COLUMN apple_approval jsonb, ADD COLUMN apple_deadline timestamptz;
ALTER TABLE mdm_access.collection_runs DROP CONSTRAINT collection_source_profile;
ALTER TABLE mdm_access.collection_runs ADD CONSTRAINT collection_source_profile CHECK(
 (source='mdm.windows' AND session_id IS NOT NULL AND request_message IS NOT NULL AND first_command IS NOT NULL AND request IS NOT NULL AND apple_approval IS NULL AND apple_deadline IS NULL)
 OR (source='agent.builtin' AND session_id IS NULL AND request_message IS NULL AND first_command IS NULL AND request IS NULL AND sealed_at IS NOT NULL AND result<>'pending' AND reason='complete' AND batch IS NOT NULL AND apple_approval IS NULL AND apple_deadline IS NULL)
 OR (source='mdm.apple' AND session_id IS NULL AND request_message IS NULL AND first_command IS NULL AND request IS NULL AND apple_approval IS NOT NULL AND apple_deadline IS NOT NULL)
);
CREATE UNIQUE INDEX collection_apple_sequence ON mdm_access.collection_runs(tenant_id,registration,source,epoch,sequence) WHERE source='mdm.apple';
CREATE INDEX collection_apple_pending ON mdm_access.collection_runs(tenant_id,apple_deadline,id) WHERE source='mdm.apple' AND sealed_at IS NULL;

-- Retain retired credential history while allowing a fenced replacement within a registration.
ALTER TABLE mdm_access.credentials DROP CONSTRAINT credentials_tenant_id_registration_key;
CREATE UNIQUE INDEX one_active_credential ON mdm_access.credentials(tenant_id,registration) WHERE state='active';
CREATE SCHEMA mdm_apple;
REVOKE ALL ON SCHEMA mdm_apple FROM PUBLIC;
CREATE TABLE mdm_apple.scep_attempts (
 tenant_id uuid NOT NULL, id uuid NOT NULL, enrollment uuid NOT NULL,
 password_version bigint NOT NULL CHECK(password_version>0),
 configuration bytea NOT NULL CHECK(octet_length(configuration)=32),
 state text NOT NULL CHECK(state IN ('prepared','consumed','bound','superseded')),
 transaction_id text CHECK(length(transaction_id) BETWEEN 1 AND 255),
 csr_digest bytea CHECK(octet_length(csr_digest)=32), spki bytea CHECK(octet_length(spki)=32),
 issuer bytea NOT NULL CHECK(octet_length(issuer)=32), serial bytea,
 fingerprint bytea CHECK(octet_length(fingerprint)=32), certificate bytea CHECK(octet_length(certificate)<=32768),
 registration uuid, expires_at timestamptz NOT NULL,
 renewal_of uuid, generation bigint CHECK(generation>0), challenge_hash bytea CHECK(octet_length(challenge_hash)=32),
 not_before bigint, not_after bigint,
 CHECK((renewal_of IS NULL AND generation IS NULL AND challenge_hash IS NULL) OR (renewal_of IS NOT NULL AND registration IS NOT NULL AND generation IS NOT NULL AND challenge_hash IS NOT NULL)),
 CHECK((not_before IS NULL AND not_after IS NULL) OR (not_before>0 AND not_after>not_before)),
 FOREIGN KEY(tenant_id,renewal_of) REFERENCES mdm_apple.scep_attempts(tenant_id,id),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,enrollment,password_version), UNIQUE(tenant_id,issuer,serial), UNIQUE(tenant_id,fingerprint),
 FOREIGN KEY(tenant_id,enrollment) REFERENCES mdm_access.requests(tenant_id,id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id),
 CHECK((state='prepared' AND transaction_id IS NULL AND csr_digest IS NULL AND spki IS NULL) OR state='superseded' OR (transaction_id IS NOT NULL AND csr_digest IS NOT NULL AND spki IS NOT NULL)),
 CHECK((fingerprint IS NULL AND serial IS NULL AND certificate IS NULL) OR (fingerprint IS NOT NULL AND serial IS NOT NULL AND certificate IS NOT NULL)),
 CHECK(state<>'bound' OR registration IS NOT NULL)
);
CREATE INDEX scep_renewal_due ON mdm_apple.scep_attempts(tenant_id,not_after,id) WHERE state='bound';
CREATE UNIQUE INDEX scep_one_renewal ON mdm_apple.scep_attempts(tenant_id,renewal_of) WHERE renewal_of IS NOT NULL AND state IN ('prepared','consumed');
CREATE UNIQUE INDEX scep_live_key ON mdm_apple.scep_attempts(tenant_id,spki) WHERE state IN ('consumed','bound');
CREATE UNIQUE INDEX scep_transaction ON mdm_apple.scep_attempts(tenant_id,transaction_id) WHERE transaction_id IS NOT NULL;
CREATE TABLE mdm_apple.devices (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, udid text NOT NULL CHECK(length(udid) BETWEEN 1 AND 255),
 state text NOT NULL CHECK(state IN ('pending_token','active','retired')),
 token bytea CHECK(octet_length(token) BETWEEN 1 AND 512), magic text CHECK(length(magic) BETWEEN 1 AND 1024),
 token_revision bigint NOT NULL DEFAULT 0 CHECK(token_revision>=0),
 push_id uuid, push_lease_until timestamptz, next_push timestamptz NOT NULL DEFAULT clock_timestamp(),
 push_configuration bytea CHECK(octet_length(push_configuration)=32), push_failures integer NOT NULL DEFAULT 0 CHECK(push_failures BETWEEN 0 AND 6),
 identity_health smallint NOT NULL DEFAULT 0 CHECK(identity_health BETWEEN 0 AND 2),
 push_status integer, push_outcome text CHECK(push_outcome IN ('accepted','retryable','unregistered','rejected')),
 PRIMARY KEY(tenant_id,registration), FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id),
 CHECK(state<>'active' OR (token IS NOT NULL AND magic IS NOT NULL))
);
CREATE UNIQUE INDEX apple_active_udid ON mdm_apple.devices(tenant_id,udid) WHERE state<>'retired';
CREATE TABLE mdm_apple.attempts (
 tenant_id uuid NOT NULL, id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 operation uuid, collection uuid, certificate uuid, phase text NOT NULL CHECK(phase IN ('collect','execute','observe','renew')),
 request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 1048576),
 state text NOT NULL CHECK(state IN ('pending','sent','not_now','acknowledged','error','superseded')),
 response bytea CHECK(octet_length(response)<=1048576), response_digest bytea CHECK(octet_length(response_digest)=32),
 received_at bigint, next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(), deadline timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,operation,phase), UNIQUE(tenant_id,collection),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id),
 FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id),
 FOREIGN KEY(tenant_id,collection) REFERENCES mdm_access.collection_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,certificate) REFERENCES mdm_apple.scep_attempts(tenant_id,id),
 UNIQUE(tenant_id,certificate),
 CHECK((phase='collect' AND collection IS NOT NULL AND operation IS NULL AND certificate IS NULL) OR (phase IN ('execute','observe') AND operation IS NOT NULL AND collection IS NULL AND certificate IS NULL) OR (phase='renew' AND certificate IS NOT NULL AND collection IS NULL AND operation IS NULL)),
 CHECK((response IS NULL)=(response_digest IS NULL))
);
CREATE INDEX apple_attempt_delivery ON mdm_apple.attempts(tenant_id,registration,next_attempt,id) WHERE state IN ('pending','sent','not_now');
CREATE TABLE mdm_apple.profiles (
 tenant_id uuid NOT NULL, device text NOT NULL, identifier text NOT NULL,
 profile uuid NOT NULL, operation uuid NOT NULL, registration uuid NOT NULL,
 version bigint NOT NULL CHECK(version>0), enabled boolean NOT NULL,
 PRIMARY KEY(tenant_id,device), UNIQUE(tenant_id,identifier),
 FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id),
 FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['scep_attempts','devices','attempts','profiles'] LOOP
  EXECUTE format('ALTER TABLE mdm_apple.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_apple.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format($policy$CREATE POLICY tenant ON mdm_apple.%I USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)$policy$,t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_apple TO mdm_access,mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_apple.scep_attempts,mdm_apple.devices,mdm_apple.attempts TO mdm_access;
GRANT UPDATE(state,response,response_digest,received_at,next_attempt) ON mdm_apple.attempts TO mdm_access;
GRANT SELECT ON mdm_access.requests TO mdm_command_runtime;
GRANT UPDATE(state,transaction_id,csr_digest,spki,serial,fingerprint,certificate,registration,not_before,not_after) ON mdm_apple.scep_attempts TO mdm_access;
GRANT UPDATE(state,token,magic,token_revision,next_push,push_id,push_lease_until,push_status,push_outcome,push_failures,identity_health) ON mdm_apple.devices TO mdm_access;
GRANT SELECT,INSERT ON mdm_apple.attempts,mdm_apple.profiles TO mdm_command_runtime;
GRANT SELECT ON mdm_apple.devices TO mdm_command_runtime;
GRANT UPDATE(state,response,response_digest,received_at,next_attempt) ON mdm_apple.attempts TO mdm_command_runtime;
GRANT UPDATE(profile,operation,registration,version,enabled) ON mdm_apple.profiles TO mdm_command_runtime;
GRANT UPDATE(token,magic,state,push_id,push_lease_until,next_push,push_status,push_outcome,push_configuration,push_failures) ON mdm_apple.devices TO mdm_command_runtime;
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
'protected_request','registration_bind','credential_revoke','device_report','enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','enrollment_read','registration_read','windows_discovery','windows_policy','windows_management','collection_read','collection_finish','software_binding','software_candidate','software_validate','software_approve','software_authorize','software_call','software_preflight','software_result','software_withdraw','software_archive','management_read','management_write','plan_preview','plan_save','authorization_write','authorization_initialize','authorization_effective_read','authorization_rules_read','authorization_groups_read','authorization_members_read','authorization_departments_read','command_accept','command_read','command_cancel','command_approve','command_dispatch','plan_execute','agent_registration','agent_report','agent_report_read','automation_completed','automation_superseded','automation_failed','apple_profile','apple_scep','apple_checkin','apple_management','apple_push','apple_renewal','collection_start'));
COMMIT;
