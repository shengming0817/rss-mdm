BEGIN;
-- This release is fresh-install only. The installer rejects every pre-existing shorter ledger
-- before this immutable unit is considered, so no deployed request is inferred as one channel.
ALTER TABLE mdm_access.requests
 ADD COLUMN channel text NOT NULL CHECK(channel IN ('agent','mdm'));

CREATE TABLE mdm_access.agent_bindings (
 tenant_id uuid NOT NULL, registration uuid NOT NULL,
 wire_version smallint NOT NULL CHECK(wire_version=1),
 capabilities text NOT NULL CHECK(capabilities='["inventory.basic.v1"]'),
 PRIMARY KEY(tenant_id,registration),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
CREATE TABLE mdm_access.agent_reports (
 tenant_id uuid NOT NULL, registration uuid NOT NULL,
 source text NOT NULL CHECK(source='agent.builtin'), epoch uuid NOT NULL,
 id uuid NOT NULL, sequence bigint NOT NULL CHECK(sequence>=0),
 scope text NOT NULL CHECK(octet_length(scope)<=4096),
 batch bytea NOT NULL CHECK(octet_length(batch) BETWEEN 1 AND 8192),
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 received_at bigint NOT NULL CHECK(received_at>=0),
 delivery_pending boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,registration,source,epoch,id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
CREATE INDEX agent_report_delivery ON mdm_access.agent_reports
 (tenant_id,registration,source,epoch,sequence,id) WHERE delivery_pending;

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['agent_bindings','agent_reports'] LOOP
  EXECUTE format('ALTER TABLE mdm_access.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_access.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_access.%I USING (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON mdm_access.agent_bindings,mdm_access.agent_reports TO mdm_access;
GRANT UPDATE(delivery_pending) ON mdm_access.agent_reports TO mdm_access;

CREATE FUNCTION mdm_access.immutable_agent_report() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(OLD)-'delivery_pending') IS DISTINCT FROM (to_jsonb(NEW)-'delivery_pending') THEN
  RAISE EXCEPTION 'sealed Agent report is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION mdm_access.immutable_agent_report() FROM PUBLIC;
CREATE TRIGGER immutable_agent_report BEFORE UPDATE ON mdm_access.agent_reports
 FOR EACH ROW EXECUTE FUNCTION mdm_access.immutable_agent_report();

ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
'protected_request','registration_bind','credential_revoke','device_report','enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','enrollment_read','registration_read','windows_discovery','windows_policy','windows_management','collection_read','collection_finish','software_binding','software_candidate','software_validate','software_approve','software_authorize','software_call','software_preflight','software_result','software_withdraw','software_archive','management_read','management_write','plan_preview','plan_save','authorization_write','authorization_initialize','authorization_effective_read','authorization_rules_read','authorization_groups_read','authorization_members_read','authorization_departments_read','command_accept','command_read','command_cancel','command_approve','command_dispatch','agent_registration','agent_report','agent_report_read'));
COMMIT;
