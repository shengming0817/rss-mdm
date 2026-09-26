CREATE SCHEMA mdm_planning;
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
CREATE TABLE mdm_planning.operations (
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
 n:='mdm_planning';
 EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',n,t);
 EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',n,t);
 EXECUTE format('CREATE POLICY tenant ON %I.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',n,t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_planning,mdm_access,mdm TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_planning TO mdm_software_driver;
GRANT SELECT ON mdm_planning.resource_references TO mdm_software_driver;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_planning TO mdm_flow_runtime;
GRANT UPDATE(revision,deleted) ON mdm_planning.scopes TO mdm_flow_runtime;
