BEGIN;
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
CREATE TABLE mdm_planning.firewall_resources (
 tenant_id uuid NOT NULL, resource text NOT NULL, version text NOT NULL, enabled boolean NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32), PRIMARY KEY(tenant_id,resource,version)
);
DO $$ DECLARE n text; t text; BEGIN
 FOR n,t IN SELECT * FROM (VALUES ('mdm_commands','attempts'),('mdm_commands','capabilities'),('mdm_commands','capability_queries'),('mdm_planning','firewall_resources')) AS names(n,t) LOOP
 EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',n,t);
 EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',n,t);
 EXECUTE format('CREATE POLICY tenant ON %I.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',n,t);
 EXECUTE format('REVOKE ALL ON %I.%I FROM PUBLIC',n,t);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON mdm_commands.attempts,mdm_commands.capabilities,mdm_commands.capability_queries TO mdm_command_runtime;
GRANT UPDATE(status,value,received_at,receipt_accepted) ON mdm_commands.attempts TO mdm_command_runtime;
GRANT UPDATE(generation,os_version,edition,session,observed_at) ON mdm_commands.capabilities TO mdm_command_runtime;
GRANT UPDATE(os_version,edition,version_status,edition_status) ON mdm_commands.capability_queries TO mdm_command_runtime;
GRANT USAGE ON SCHEMA mdm_planning TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_planning.firewall_resources TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_commands TO mdm_flow_runtime;
GRANT SELECT ON mdm_commands.capabilities TO mdm_flow_runtime;
-- Narrow read projection; the RSS component still admits only its command runtime.
ALTER TABLE mdm_automation.automation_jobs ADD COLUMN failure_detail jsonb;
ALTER TABLE mdm_automation.automation_jobs DROP CONSTRAINT automation_jobs_failure_check;
ALTER TABLE mdm_automation.automation_jobs ADD CONSTRAINT automation_jobs_failure_check CHECK(failure IN('superseded','capacity_exceeded','source_unavailable','invalid_input','storage_invariant','automation_suspended','configuration_target_limit','capability_unknown','platform_unsupported','stale_plan','owner_conflict'));
GRANT UPDATE(failure_detail) ON mdm_automation.automation_jobs TO mdm_flow_runtime;
COMMIT;
