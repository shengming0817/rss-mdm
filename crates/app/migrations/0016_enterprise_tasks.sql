BEGIN;
CREATE TABLE mdm_planning.action_plans (
 tenant_id uuid NOT NULL, id uuid NOT NULL,
 resource text NOT NULL, version text NOT NULL,
 document jsonb NOT NULL CHECK(octet_length(document::text)<=4194304),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 author jsonb NOT NULL, author_approvals jsonb NOT NULL,
 reviewer jsonb, reviewer_approvals jsonb,
 active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,id),
 CHECK((reviewer IS NULL)=(reviewer_approvals IS NULL)),
 CHECK(reviewer IS NULL OR reviewer<>author)
);
CREATE TABLE mdm_commands.action_progress (
 tenant_id uuid NOT NULL, id uuid NOT NULL,
 scan_at bigint NOT NULL CHECK(scan_at>=-1),
 recovery_after uuid,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,id) REFERENCES mdm_planning.action_plans(tenant_id,id)
);
CREATE TABLE mdm_planning.action_receipts (
 tenant_id uuid NOT NULL, actor text NOT NULL, id uuid NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=262144),
 PRIMARY KEY(tenant_id,actor,id)
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
 FOREIGN KEY(tenant_id,plan) REFERENCES mdm_planning.action_plans(tenant_id,id),
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
 FOREACH t IN ARRAY ARRAY['action_progress','action_runs','action_receipts','action_attempts'] LOOP
 EXECUTE format('ALTER TABLE mdm_commands.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_commands.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_commands.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON mdm_commands.action_runs,mdm_commands.action_receipts,mdm_commands.action_attempts TO mdm_command_runtime;
GRANT SELECT ON mdm_planning.action_plans TO mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_planning.action_plans,mdm_planning.action_receipts,mdm_commands.action_runs,mdm_commands.action_progress TO mdm_flow_runtime;
GRANT SELECT ON mdm_access.agent_bindings,mdm_access.authorization_rules,mdm_access.user_groups TO mdm_flow_runtime;
GRANT UPDATE(reviewer,reviewer_approvals,active) ON mdm_planning.action_plans TO mdm_flow_runtime;
GRANT SELECT,INSERT ON mdm_commands.action_progress TO mdm_command_runtime;
GRANT UPDATE(scan_at,recovery_after) ON mdm_commands.action_progress TO mdm_command_runtime;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['action_plans','action_receipts'] LOOP
 EXECUTE format('ALTER TABLE mdm_planning.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_planning.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_planning.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_planning TO mdm_command_runtime;

GRANT UPDATE(state,result,gateway_accepted) ON mdm_commands.action_runs TO mdm_command_runtime;
GRANT UPDATE(permit) ON mdm_commands.action_attempts TO mdm_command_runtime;
GRANT USAGE ON SCHEMA mdm_resource TO mdm_command_runtime;
GRANT SELECT ON mdm_resource.aggregates,mdm_resource.immutable,mdm_access.agent_bindings TO mdm_command_runtime;
GRANT SELECT ON mdm_planning.action_plans TO mdm_flow_runtime;
-- Scope snapshots are resolved by the planning owner under the caller's transaction.
CREATE FUNCTION mdm_planning.action_targets(p_scope uuid,p_revision bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $targets$
DECLARE s record; r record; targets jsonb; token record;
BEGIN
 SELECT * INTO s FROM mdm_planning.scopes
 WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND id=p_scope FOR UPDATE;
 IF NOT FOUND OR s.deleted THEN RETURN jsonb_build_object('missing',true); END IF;
 IF s.resolution IS NULL THEN RETURN jsonb_build_object('rejection','unavailable'); END IF;
 IF s.resolution_revision<>p_revision THEN RETURN jsonb_build_object('rejection','stale'); END IF;
 SELECT * INTO r FROM mdm_planning.scope_runs WHERE tenant_id=s.tenant_id AND id=s.resolution;
 IF NOT FOUND OR r.phase<>'published' OR r.result_fingerprint IS NULL OR r.definition_revision<>s.revision THEN RETURN jsonb_build_object('rejection','stale'); END IF;
 IF EXISTS(SELECT 1 FROM mdm_access.asset_authority_history h WHERE h.tenant_id=s.tenant_id AND h.revision>r.asset_watermark
 AND EXISTS(SELECT 1 FROM mdm_planning.scope_source_members m WHERE (m.tenant_id,m.run,m.device)=(r.tenant_id,r.id,h.device))) THEN RETURN jsonb_build_object('rejection','stale'); END IF;
 FOR token IN
 SELECT 'group-'||v.kind||'.'||(source->'reference'->>'id') AS id,(source->>v.field)::bigint AS revision
 FROM jsonb_array_elements(r.input->'sources') source
 CROSS JOIN (VALUES('definition','definitionVersion'),('members','memberVersion'),('authority','authorityVersion')) v(kind,field)
 WHERE source->'reference'->>'kind'='group'
 LOOP
 IF NOT EXISTS(SELECT 1 FROM mdm_policy.reference_heads h WHERE h.tenant_id=s.tenant_id AND h.id=token.id AND h.revision=token.revision) THEN RETURN jsonb_build_object('rejection','stale'); END IF;
 END LOOP;
 SELECT coalesce(jsonb_agg(device ORDER BY device COLLATE "C"),'[]'::jsonb) INTO targets FROM (
 SELECT device FROM mdm_planning.scope_results WHERE tenant_id=s.tenant_id AND run=r.id AND matched ORDER BY device COLLATE "C" LIMIT 257) bounded;
 RETURN jsonb_build_object('devices',targets,'scope',jsonb_build_object('id',s.id,'resolution',r.id,'resolutionRevision',s.resolution_revision,'definitionRevision',r.definition_revision,'sources',r.input->'sources','fingerprint',encode(r.result_fingerprint,'hex')));
END;
$targets$;
REVOKE ALL ON FUNCTION mdm_planning.action_targets(uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_planning.action_targets(uuid,bigint) TO mdm_flow_runtime;
COMMIT;
