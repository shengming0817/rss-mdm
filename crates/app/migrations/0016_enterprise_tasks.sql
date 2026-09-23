BEGIN;
CREATE TABLE mdm_commands.action_plans (
 tenant_id uuid NOT NULL, id uuid NOT NULL,
 resource text NOT NULL, version text NOT NULL,
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4194304),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 author jsonb NOT NULL, author_approvals jsonb NOT NULL,
 reviewer jsonb, reviewer_approvals jsonb,
 active boolean NOT NULL DEFAULT true,
 recovery_after uuid,
 scan_at bigint NOT NULL CHECK(scan_at>=-1),
 PRIMARY KEY(tenant_id,id),
 CHECK((reviewer IS NULL)=(reviewer_approvals IS NULL)),
 CHECK(reviewer IS NULL OR reviewer<>author)
);
CREATE TABLE mdm_commands.action_runs (
 tenant_id uuid NOT NULL, id uuid NOT NULL, plan uuid NOT NULL,
 device text NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 occurrence text NOT NULL CHECK(octet_length(occurrence) BETWEEN 1 AND 256),
 created_at bigint NOT NULL CHECK(created_at>=0),
 available_at bigint NOT NULL CHECK(available_at>=0), deadline bigint NOT NULL CHECK(deadline>available_at),
 state jsonb NOT NULL CHECK(octet_length(state::text)<=4096),
 gateway_accepted boolean NOT NULL DEFAULT false,
 dispatch_fingerprint bytea NOT NULL CHECK(octet_length(dispatch_fingerprint)=32),
 result jsonb CHECK(octet_length(result::text)<=1114112),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,plan,occurrence,device),
 FOREIGN KEY(tenant_id,plan) REFERENCES mdm_commands.action_plans(tenant_id,id),
 FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
CREATE INDEX action_due ON mdm_commands.action_runs(tenant_id,registration,available_at,id);
CREATE TABLE mdm_commands.action_receipts (
 tenant_id uuid NOT NULL, actor text NOT NULL, id uuid NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=262144),
 PRIMARY KEY(tenant_id,actor,id)
);
CREATE TABLE mdm_commands.action_attempts (
 tenant_id uuid NOT NULL, id uuid NOT NULL, run uuid NOT NULL,
 registration uuid NOT NULL, claimed_at bigint NOT NULL CHECK(claimed_at>=0),
 offer jsonb NOT NULL CHECK(octet_length(offer::text)<=262144),
 permit jsonb CHECK(octet_length(permit::text)<=262144),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,run) REFERENCES mdm_commands.action_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['action_plans','action_runs','action_receipts','action_attempts'] LOOP
 EXECUTE format('ALTER TABLE mdm_commands.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_commands.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_commands.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON mdm_commands.action_plans,mdm_commands.action_runs,mdm_commands.action_receipts,mdm_commands.action_attempts TO mdm_command_runtime;
GRANT UPDATE(reviewer,reviewer_approvals,active,scan_at,recovery_after) ON mdm_commands.action_plans TO mdm_command_runtime;
GRANT UPDATE(state,result,gateway_accepted) ON mdm_commands.action_runs TO mdm_command_runtime;
GRANT UPDATE(permit) ON mdm_commands.action_attempts TO mdm_command_runtime;
GRANT USAGE ON SCHEMA mdm_resource TO mdm_command_runtime;
GRANT SELECT ON mdm_resource.aggregates,mdm_resource.immutable,mdm_access.agent_bindings TO mdm_command_runtime;
GRANT SELECT ON mdm_commands.action_plans TO mdm_management_runtime;
COMMIT;
