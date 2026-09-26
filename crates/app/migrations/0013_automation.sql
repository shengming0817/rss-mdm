BEGIN;
DROP TABLE mdm_planning.plan_references;
DROP TABLE mdm_planning.previews;
CREATE INDEX asset_authority_changes ON mdm_access.asset_authority_history(tenant_id,revision,device);
CREATE TABLE mdm_flow.cursor_keys (
 tenant_id uuid PRIMARY KEY, secret bytea NOT NULL CHECK(octet_length(secret)=32)
);
CREATE TABLE mdm_automation.automation_jobs (
 tenant_id uuid NOT NULL, id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN('group','group_preview','scope','policy','asset_query')),
 target text NOT NULL CHECK(octet_length(target) BETWEEN 1 AND 256),
 input jsonb NOT NULL CHECK(octet_length(input::text)<=1048576),
 forwarded boolean NOT NULL DEFAULT false, completed boolean NOT NULL DEFAULT false,
 cursor text,
 authority_revision bigint NOT NULL DEFAULT 0 CHECK(authority_revision>=0),
 failure text CHECK(failure IN('superseded','capacity_exceeded','source_unavailable','invalid_input','storage_invariant','automation_suspended')),
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX automation_jobs_pending ON mdm_automation.automation_jobs(tenant_id,id) WHERE NOT forwarded;
CREATE TABLE mdm_planning.group_fields (
 tenant_id uuid NOT NULL, group_id uuid NOT NULL, field text NOT NULL,
 PRIMARY KEY(tenant_id,group_id,field),
 FOREIGN KEY(tenant_id,group_id) REFERENCES mdm_group.groups(tenant_id,id)
);
CREATE INDEX group_fields_field ON mdm_planning.group_fields(tenant_id,field,group_id);
CREATE TABLE mdm_planning.asset_dispatch (
 tenant_id uuid PRIMARY KEY, consumed bigint NOT NULL DEFAULT 0,
 watermark bigint NOT NULL DEFAULT 0, group_cursor uuid,
 failure text CHECK(failure='automation_suspended'),
 failure_generation bigint NOT NULL DEFAULT 0 CHECK(failure_generation>=0),
 phase text NOT NULL DEFAULT 'groups' CHECK(phase IN('groups','devices')),
 CHECK(consumed>=0 AND watermark>=consumed)
);
CREATE TABLE mdm_planning.scope_sources (
 tenant_id uuid NOT NULL, scope uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN('group','device')), target text NOT NULL,
 PRIMARY KEY(tenant_id,scope,kind,target),
 FOREIGN KEY(tenant_id,scope) REFERENCES mdm_planning.scopes(tenant_id,id)
);
CREATE INDEX scope_sources_target ON mdm_planning.scope_sources(tenant_id,kind,target,scope);
CREATE TABLE mdm_planning.scope_runs (
 tenant_id uuid NOT NULL, id uuid NOT NULL, scope uuid NOT NULL, definition_revision bigint NOT NULL,
 asset_watermark bigint NOT NULL, input jsonb NOT NULL CHECK(octet_length(input::text)<=1048576),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 identity_revision bigint NOT NULL DEFAULT 0 CHECK(identity_revision>=0),
 result_fingerprint bytea CHECK(result_fingerprint IS NULL OR octet_length(result_fingerprint)=32),
 phase text NOT NULL CHECK(phase IN('sources','evaluate','ready','published','superseded')),
 source_index integer NOT NULL DEFAULT 0 CHECK(source_index BETWEEN 0 AND 1000),
 source_cursor text, evaluation_cursor text,
 object_count bigint NOT NULL DEFAULT 0 CHECK(object_count BETWEEN 0 AND 1000000),
 member_count bigint NOT NULL DEFAULT 0 CHECK(member_count BETWEEN 0 AND object_count),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,scope) REFERENCES mdm_planning.scopes(tenant_id,id)
);
CREATE TABLE mdm_planning.scope_source_members (
 tenant_id uuid NOT NULL, run uuid NOT NULL, source integer NOT NULL CHECK(source BETWEEN 0 AND 999),
 device text COLLATE "C" NOT NULL CHECK(octet_length(device) BETWEEN 1 AND 256),
 PRIMARY KEY(tenant_id,run,source,device),
 FOREIGN KEY(tenant_id,run) REFERENCES mdm_planning.scope_runs(tenant_id,id)
);
CREATE INDEX scope_source_members_devices ON mdm_planning.scope_source_members(tenant_id,run,device,source);
CREATE TABLE mdm_planning.scope_results (
 tenant_id uuid NOT NULL, run uuid NOT NULL, device text COLLATE "C" NOT NULL, matched boolean NOT NULL,
 explanation jsonb NOT NULL CHECK(octet_length(explanation::text)<=1048576),
 PRIMARY KEY(tenant_id,run,device), FOREIGN KEY(tenant_id,run) REFERENCES mdm_planning.scope_runs(tenant_id,id)
);
CREATE INDEX scope_results_members ON mdm_planning.scope_results(tenant_id,run,device) WHERE matched;
ALTER TABLE mdm_planning.scopes ADD COLUMN resolution uuid;
ALTER TABLE mdm_planning.scopes ADD COLUMN resolution_revision bigint NOT NULL DEFAULT 0 CHECK(resolution_revision>=0);
ALTER TABLE mdm_planning.scopes ADD FOREIGN KEY(tenant_id,resolution) REFERENCES mdm_planning.scope_runs(tenant_id,id);
CREATE TABLE mdm_planning.policy_assignments (
 tenant_id uuid NOT NULL, policy text NOT NULL, scope uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(tenant_id,policy), FOREIGN KEY(tenant_id,scope) REFERENCES mdm_planning.scopes(tenant_id,id),
 FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.aggregates(tenant_id,id)
);
CREATE INDEX policy_assignments_scope ON mdm_planning.policy_assignments(tenant_id,scope,policy);
CREATE TABLE mdm_planning.candidate_heads (
 tenant_id uuid NOT NULL, policy text NOT NULL, desired uuid NOT NULL, candidate uuid,
 PRIMARY KEY(tenant_id,policy), FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.aggregates(tenant_id,id),
 FOREIGN KEY(tenant_id,desired) REFERENCES mdm_automation.automation_jobs(tenant_id,id),
 FOREIGN KEY(tenant_id,candidate) REFERENCES mdm_automation.automation_jobs(tenant_id,id)
);
CREATE TABLE mdm_assets.asset_query_runs (
 tenant_id uuid NOT NULL,id uuid NOT NULL,total bigint NOT NULL DEFAULT 0 CHECK(total BETWEEN 0 AND 1000000),
 matched bigint NOT NULL DEFAULT 0 CHECK(matched BETWEEN 0 AND total),unknown bigint NOT NULL DEFAULT 0 CHECK(unknown BETWEEN 0 AND total),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,id) REFERENCES mdm_automation.automation_jobs(tenant_id,id)
);
CREATE TABLE mdm_assets.asset_query_results (
 tenant_id uuid NOT NULL,run uuid NOT NULL,device text COLLATE "C" NOT NULL CHECK(octet_length(device) BETWEEN 1 AND 256),
 sort_key bytea NOT NULL CHECK(octet_length(sort_key)<=1024),document bytea NOT NULL CHECK(octet_length(document)<=1048576),digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,run,device),FOREIGN KEY(tenant_id,run) REFERENCES mdm_assets.asset_query_runs(tenant_id,id)
);
CREATE INDEX asset_query_results_order ON mdm_assets.asset_query_results(tenant_id,run,sort_key,device);
CREATE TABLE mdm_assets.asset_query_facets (
 tenant_id uuid NOT NULL,run uuid NOT NULL,kind text NOT NULL CHECK(kind IN('os_versions','channels','asset_states')),
 label text COLLATE "C" NOT NULL CHECK(octet_length(label)<=256),total bigint NOT NULL CHECK(total>0),
 PRIMARY KEY(tenant_id,run,kind,label),FOREIGN KEY(tenant_id,run) REFERENCES mdm_assets.asset_query_runs(tenant_id,id)
);
DO $$ DECLARE t text; n text; BEGIN
 FOREACH t IN ARRAY ARRAY['cursor_keys','automation_jobs','group_fields','asset_dispatch','scope_sources','scope_runs','scope_source_members','scope_results','policy_assignments','candidate_heads','asset_query_runs','asset_query_results','asset_query_facets'] LOOP
 n:=CASE t WHEN 'operations' THEN 'mdm_flow' WHEN 'cursor_keys' THEN 'mdm_flow' WHEN 'automation_jobs' THEN 'mdm_automation' WHEN 'saved_queries' THEN 'mdm_assets' WHEN 'asset_query_runs' THEN 'mdm_assets' WHEN 'asset_query_results' THEN 'mdm_assets' WHEN 'asset_query_facets' THEN 'mdm_assets' ELSE 'mdm_planning' END;
  EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',n,t);
  EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',n,t);
  EXECUTE format('CREATE POLICY tenant ON %I.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',n,t);
  EXECUTE format('REVOKE ALL ON %I.%I FROM PUBLIC',n,t);
  EXECUTE format('GRANT SELECT,INSERT ON %I.%I TO mdm_flow_runtime',n,t);
 END LOOP;
END $$;
GRANT UPDATE(forwarded,completed,failure,cursor,authority_revision) ON mdm_automation.automation_jobs TO mdm_flow_runtime;
GRANT UPDATE(consumed,watermark,group_cursor,phase,failure,failure_generation) ON mdm_planning.asset_dispatch TO mdm_flow_runtime;
GRANT UPDATE(phase,source_index,source_cursor,evaluation_cursor,object_count,member_count,identity_revision,result_fingerprint) ON mdm_planning.scope_runs TO mdm_flow_runtime;
GRANT UPDATE(resolution,resolution_revision) ON mdm_planning.scopes TO mdm_flow_runtime;
GRANT UPDATE(scope,revision) ON mdm_planning.policy_assignments TO mdm_flow_runtime;
GRANT UPDATE(desired,candidate) ON mdm_planning.candidate_heads TO mdm_flow_runtime;
GRANT DELETE ON mdm_planning.group_fields,mdm_planning.scope_sources TO mdm_flow_runtime;
GRANT UPDATE(total,matched,unknown) ON mdm_assets.asset_query_runs TO mdm_flow_runtime;
GRANT UPDATE(total) ON mdm_assets.asset_query_facets TO mdm_flow_runtime;
COMMIT;
