BEGIN;
CREATE SCHEMA mdm_commands;
REVOKE ALL ON SCHEMA mdm_commands FROM PUBLIC;
CREATE TABLE mdm_commands.devices (
 tenant_id uuid NOT NULL, device text NOT NULL, command_device uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0), epoch bigint NOT NULL CHECK(epoch>0),
 registration uuid NOT NULL, registration_generation bigint NOT NULL CHECK(registration_generation>0),
 recovery_after text,
 PRIMARY KEY(tenant_id,device), UNIQUE(tenant_id,command_device),
 FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
CREATE TABLE mdm_commands.operations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, device text NOT NULL,
 request jsonb NOT NULL CHECK(octet_length(request::text)<=4096),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 registration uuid NOT NULL, registration_generation bigint NOT NULL CHECK(registration_generation>0),
 generation bigint NOT NULL CHECK(generation>0), epoch bigint NOT NULL CHECK(epoch>0),
 approval jsonb NOT NULL CHECK(octet_length(approval::text)<=1048576),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 dispatch_fingerprint bytea NOT NULL CHECK(octet_length(dispatch_fingerprint)=32),
 gateway_accepted boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,device) REFERENCES mdm_commands.devices(tenant_id,device)
);
CREATE TABLE mdm_commands.requests (
 tenant_id uuid NOT NULL, id uuid NOT NULL, operation uuid NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32), response jsonb NOT NULL,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id)
);
CREATE TABLE mdm_commands.attempts (
 tenant_id uuid NOT NULL, operation uuid NOT NULL, ordinal bigint NOT NULL CHECK(ordinal>0),
 id uuid NOT NULL, collection uuid NOT NULL, credential uuid NOT NULL,
 PRIMARY KEY(tenant_id,operation,ordinal), UNIQUE(tenant_id,id), UNIQUE(tenant_id,operation,collection),
 FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id),
 FOREIGN KEY(tenant_id,collection) REFERENCES mdm_access.collection_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,credential) REFERENCES mdm_access.credentials(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['devices','operations','requests','attempts'] LOOP
 EXECUTE format('ALTER TABLE mdm_commands.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_commands.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_commands.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_commands,rss_device_command,rss_reconcile,rss_transactional_messaging,mdm_access TO mdm_command_runtime;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_commands TO mdm_command_runtime;
GRANT UPDATE(generation,epoch,registration,registration_generation,recovery_after) ON mdm_commands.devices TO mdm_command_runtime;
GRANT UPDATE(approval,revision,gateway_accepted) ON mdm_commands.operations TO mdm_command_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA rss_device_command,rss_reconcile TO mdm_command_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_device_command,rss_reconcile TO mdm_command_runtime;
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO mdm_command_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO mdm_command_runtime;
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb),rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) TO mdm_command_runtime;
GRANT SELECT ON mdm_access.devices,mdm_access.registrations,mdm_access.credentials,mdm_access.report_sources,mdm_access.enrollment_intents,mdm_access.enrollment_certificates,mdm_access.management_sessions,mdm_access.management_messages,mdm_access.collection_runs,mdm_access.authorization_rules,mdm_access.user_groups TO mdm_command_runtime;
GRANT INSERT ON mdm_access.management_sessions,mdm_access.management_messages,mdm_access.collection_runs,mdm_access.audit TO mdm_command_runtime;
GRANT UPDATE(next_sequence,next_command) ON mdm_access.report_sources TO mdm_command_runtime;
GRANT UPDATE(server_nonce) ON mdm_access.enrollment_certificates TO mdm_command_runtime;
GRANT UPDATE(state,last_message,client_authenticated,correlation,nonce,run_id) ON mdm_access.management_sessions TO mdm_command_runtime;
GRANT UPDATE(attempts,result,reason,batch,digest,sealed_at,delivery_pending) ON mdm_access.collection_runs TO mdm_command_runtime;
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
'protected_request','registration_bind','credential_revoke','device_report','enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','enrollment_read','registration_read','windows_discovery','windows_policy','windows_management','collection_read','collection_finish','software_binding','software_candidate','software_validate','software_approve','software_authorize','software_call','software_preflight','software_result','software_withdraw','software_archive','management_read','management_write','plan_preview','plan_save','authorization_write','authorization_initialize','authorization_effective_read','authorization_rules_read','authorization_groups_read','authorization_members_read','authorization_departments_read','command_accept','command_read','command_cancel','command_approve','command_dispatch'));
COMMIT;
