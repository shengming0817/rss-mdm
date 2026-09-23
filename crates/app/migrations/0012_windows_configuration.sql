BEGIN;
ALTER TABLE mdm_access.audit ADD COLUMN plan uuid;
ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
'protected_request','registration_bind','credential_revoke','device_report','enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','enrollment_read','registration_read','windows_discovery','windows_policy','windows_management','collection_read','collection_finish','software_binding','software_candidate','software_validate','software_approve','software_authorize','software_call','software_preflight','software_result','software_withdraw','software_archive','management_read','management_write','plan_preview','plan_save','authorization_write','authorization_initialize','authorization_effective_read','authorization_rules_read','authorization_groups_read','authorization_members_read','authorization_departments_read','command_accept','command_read','command_cancel','command_approve','command_dispatch','plan_execute'));
-- One-way cutover: never reinterpret an in-flight old dispatch contract.
CREATE TABLE mdm_commands.attempt_history (LIKE mdm_commands.attempts INCLUDING ALL);
DO $$ DECLARE t text; BEGIN
 FOR t IN SELECT jsonb_array_elements_text(configuration->'tenants') FROM public.mdm_installation LOOP
 PERFORM set_config('rss.tenant_id',t,true);
 UPDATE mdm_commands.operations SET request=jsonb_build_object('operationId',request->'operationId','deadline',request->'deadline','task',jsonb_build_object('kind','state_verify','field',request->'field','expectedValue',request->'expectedValue')),
 approval=approval||'{"permission":"state_verify"}'::jsonb;
 INSERT INTO mdm_commands.attempt_history SELECT * FROM mdm_commands.attempts;
 UPDATE mdm_management.previews SET document=document||'{"configuration":null}'::jsonb;
 END LOOP;
END $$;
DROP TABLE mdm_commands.attempts;
CREATE TABLE mdm_commands.attempts (
 tenant_id uuid NOT NULL, id uuid NOT NULL, operation uuid NOT NULL, ordinal bigint NOT NULL CHECK(ordinal>0),
 credential uuid NOT NULL, session bigint NOT NULL, message bigint NOT NULL, command bigint NOT NULL,
 phase text NOT NULL CHECK(phase IN('execute','observe')), uri text NOT NULL,
 status integer, value text, received_at bigint, receipt_accepted boolean, request bytea NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,operation,ordinal),
 FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id),
 FOREIGN KEY(tenant_id,credential) REFERENCES mdm_access.credentials(tenant_id,id),
 CHECK(status IS NULL OR status BETWEEN 100 AND 599),CHECK(value IS NULL OR octet_length(value)<=4096)
);
CREATE INDEX native_session_receipts ON mdm_commands.attempts(tenant_id,session,operation) WHERE receipt_accepted;
CREATE TABLE mdm_commands.capabilities (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL,
 os_version text NOT NULL, edition integer NOT NULL, session bigint NOT NULL, observed_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,registration), FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
CREATE TABLE mdm_commands.capability_queries (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL, session bigint NOT NULL,
 request bytea NOT NULL, version_command bigint NOT NULL, edition_command bigint NOT NULL,
 os_version text, edition text, version_status integer, edition_status integer,
 session_id text GENERATED ALWAYS AS (session::text) STORED NOT NULL,
 FOREIGN KEY(tenant_id,registration,session_id) REFERENCES mdm_access.management_sessions(tenant_id,registration,session_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
 PRIMARY KEY(tenant_id,registration,session), FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
CREATE TABLE mdm_management.firewall_resources (
 tenant_id uuid NOT NULL, resource text NOT NULL, version text NOT NULL, enabled boolean NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32), PRIMARY KEY(tenant_id,resource,version)
);
CREATE TABLE mdm_management.firewall_versions (
 tenant_id uuid NOT NULL, policy text NOT NULL, version bigint NOT NULL,
 resource text NOT NULL, resource_version text NOT NULL,
 PRIMARY KEY(tenant_id,policy,version),
 FOREIGN KEY(tenant_id,resource,resource_version) REFERENCES mdm_management.firewall_resources(tenant_id,resource,version)
);
ALTER TABLE mdm_commands.requests ALTER COLUMN operation DROP NOT NULL;
ALTER TABLE mdm_commands.requests ADD COLUMN plan uuid;
ALTER TABLE mdm_commands.requests ADD FOREIGN KEY(tenant_id,plan) REFERENCES mdm_management.previews(tenant_id,id);
ALTER TABLE mdm_commands.requests ADD CHECK((operation IS NULL)<>(plan IS NULL));
CREATE TABLE mdm_commands.plan_executions (
 tenant_id uuid NOT NULL, plan uuid NOT NULL, policy text NOT NULL, policy_revision bigint NOT NULL,
 request uuid NOT NULL,
 PRIMARY KEY(tenant_id,plan), UNIQUE(tenant_id,request),
 FOREIGN KEY(tenant_id,plan) REFERENCES mdm_management.previews(tenant_id,id),
 FOREIGN KEY(tenant_id,request) REFERENCES mdm_commands.requests(tenant_id,id)
);
CREATE TABLE mdm_commands.firewall_owners (
 tenant_id uuid NOT NULL, device text NOT NULL,
 node text NOT NULL CHECK(node='./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall'),
 policy text NOT NULL, version bigint NOT NULL CHECK(version>0), operation uuid NOT NULL,
 PRIMARY KEY(tenant_id,device,node),
 FOREIGN KEY(tenant_id,operation) REFERENCES mdm_commands.operations(tenant_id,id),
 FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.aggregates(tenant_id,id)
);
DO $$ DECLARE n text; t text; BEGIN
 FOR n,t IN SELECT * FROM (VALUES ('mdm_commands','attempts'),('mdm_commands','attempt_history'),('mdm_commands','capabilities'),('mdm_commands','capability_queries'),('mdm_commands','plan_executions'),('mdm_commands','firewall_owners'),('mdm_management','firewall_resources'),('mdm_management','firewall_versions')) AS names(n,t) LOOP
 EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',n,t);
 EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',n,t);
 EXECUTE format('CREATE POLICY tenant ON %I.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',n,t);
 EXECUTE format('REVOKE ALL ON %I.%I FROM PUBLIC',n,t);
 END LOOP;
END $$;
GRANT SELECT,INSERT,DELETE ON mdm_commands.firewall_owners TO mdm_command_runtime;
GRANT UPDATE(version,operation) ON mdm_commands.firewall_owners TO mdm_command_runtime;
GRANT SELECT ON mdm_commands.attempt_history TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_commands.attempts,mdm_commands.capabilities,mdm_commands.capability_queries,mdm_commands.plan_executions TO mdm_command_runtime;
GRANT UPDATE(status,value,received_at,receipt_accepted) ON mdm_commands.attempts TO mdm_command_runtime;
GRANT UPDATE(generation,os_version,edition,session,observed_at) ON mdm_commands.capabilities TO mdm_command_runtime;
GRANT UPDATE(os_version,edition,version_status,edition_status) ON mdm_commands.capability_queries TO mdm_command_runtime;
GRANT USAGE ON SCHEMA mdm_management,mdm_policy,mdm_group TO mdm_command_runtime;
GRANT SELECT ON mdm_management.previews,mdm_management.plan_references,mdm_management.firewall_resources,mdm_management.firewall_versions,mdm_policy.aggregates,mdm_group.groups,mdm_management.scopes TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_management.firewall_resources,mdm_management.firewall_versions TO mdm_management_runtime;
GRANT USAGE ON SCHEMA mdm_commands TO mdm_management_runtime;
GRANT SELECT ON mdm_commands.capabilities TO mdm_management_runtime;
-- Narrow read projection; the RSS component still admits only its command runtime.
CREATE FUNCTION mdm_commands.policy_facts(p_policy text) RETURNS TABLE(device text,version bigint,digest bytea,status text,write_status integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,mdm_commands AS $facts$
SELECT o.device,(o.request->'task'->>'version')::bigint AS version,r.digest,d.status,(SELECT a.status FROM mdm_commands.attempts a WHERE a.tenant_id=o.tenant_id AND a.operation=o.id AND a.phase='execute' AND a.receipt_accepted ORDER BY ordinal DESC LIMIT 1) AS write_status FROM mdm_commands.operations o JOIN mdm_management.firewall_versions v ON v.tenant_id=o.tenant_id AND v.policy=o.request->'task'->>'policy' AND v.version=(o.request->'task'->>'version')::bigint JOIN mdm_management.firewall_resources r ON(r.tenant_id,r.resource,r.version)=(v.tenant_id,v.resource,v.resource_version) JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND o.request->'task'->>'kind'='firewall' AND o.request->'task'->>'policy'=p_policy ORDER BY o.id;
$facts$;
REVOKE ALL ON FUNCTION mdm_commands.policy_facts(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_commands.policy_facts(text) TO mdm_management_runtime;
ALTER TABLE mdm_management.plan_references ADD COLUMN saved_revision bigint NOT NULL DEFAULT 0;
ALTER TABLE mdm_management.plan_references ALTER COLUMN saved_revision DROP DEFAULT;
COMMIT;
