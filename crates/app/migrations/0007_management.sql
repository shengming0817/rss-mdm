BEGIN;
CREATE SCHEMA mdm_planning;
CREATE SCHEMA mdm_flow;
CREATE SCHEMA mdm_automation;
CREATE SCHEMA mdm_assets;
REVOKE ALL ON SCHEMA mdm_flow,mdm_automation,mdm_assets FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_flow,mdm_automation,mdm_assets TO mdm_planning_runtime;
REVOKE ALL ON SCHEMA mdm_planning FROM PUBLIC;
CREATE TABLE mdm_planning.scopes (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), deleted boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_planning.scope_versions (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0), definition jsonb NOT NULL CHECK(octet_length(definition::text)<=65536),
 PRIMARY KEY(tenant_id,id,revision), FOREIGN KEY(tenant_id,id) REFERENCES mdm_planning.scopes(tenant_id,id)
);
CREATE TABLE mdm_planning.previews (
 tenant_id uuid NOT NULL, id uuid NOT NULL, scope uuid NOT NULL, scope_revision bigint NOT NULL,
 document jsonb NOT NULL CHECK(octet_length(document::text)<=8388608),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,scope,scope_revision) REFERENCES mdm_planning.scope_versions(tenant_id,id,revision)
);
CREATE TABLE mdm_flow.operations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=8388608), PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_planning.plan_references (
 tenant_id uuid NOT NULL, preview uuid NOT NULL, policy text NOT NULL, plan bytea NOT NULL CHECK(octet_length(plan)=32),
 PRIMARY KEY(tenant_id,preview), FOREIGN KEY(tenant_id,preview) REFERENCES mdm_planning.previews(tenant_id,id)
);
CREATE TABLE mdm_planning.resource_references (
 tenant_id uuid NOT NULL, resource text NOT NULL, version text NOT NULL, policy text NOT NULL,
 PRIMARY KEY(tenant_id,resource,version,policy)
);
DO $$ DECLARE t text; n text; BEGIN
 FOREACH t IN ARRAY ARRAY['scopes','scope_versions','previews','operations','plan_references','resource_references'] LOOP
 n:=CASE t WHEN 'operations' THEN 'mdm_flow' WHEN 'cursor_keys' THEN 'mdm_flow' WHEN 'automation_jobs' THEN 'mdm_automation' WHEN 'saved_queries' THEN 'mdm_assets' WHEN 'asset_query_runs' THEN 'mdm_assets' WHEN 'asset_query_results' THEN 'mdm_assets' WHEN 'asset_query_facets' THEN 'mdm_assets' ELSE 'mdm_planning' END;
 EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',n,t);
 EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',n,t);
 EXECUTE format('CREATE POLICY tenant ON %I.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',n,t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_planning,mdm_access,mdm TO mdm_planning_runtime;
GRANT USAGE ON SCHEMA mdm_planning TO mdm_software_driver;
GRANT SELECT ON mdm_planning.resource_references TO mdm_software_driver;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_planning,mdm_flow TO mdm_planning_runtime;
GRANT UPDATE(revision,deleted) ON mdm_planning.scopes TO mdm_planning_runtime;
GRANT USAGE ON SCHEMA mdm_software_composition TO mdm_planning_runtime;
GRANT SELECT ON mdm_software_composition.subjects TO mdm_planning_runtime;
GRANT SELECT ON mdm_access.devices,mdm_access.registrations,mdm_access.report_sources,mdm_access.collection_runs,mdm.inventory TO mdm_planning_runtime;
ALTER TABLE mdm_access.grants DROP CONSTRAINT grants_device_check;
ALTER TABLE mdm_access.grants ADD CHECK(octet_length(device) BETWEEN 1 AND 256 AND device !~ '[[:cntrl:]]');
ALTER TABLE mdm_access.devices DROP CONSTRAINT devices_id_check;
ALTER TABLE mdm_access.devices ADD CHECK(octet_length(id) BETWEEN 1 AND 256 AND id !~ '[[:cntrl:]]');
COMMIT;
