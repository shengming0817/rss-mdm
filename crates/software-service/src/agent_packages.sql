BEGIN;
CREATE SCHEMA mdm_agent_packages;
REVOKE ALL ON SCHEMA mdm_agent_packages FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_agent_packages TO mdm_access,mdm_flow_runtime;
CREATE TABLE mdm_agent_packages.releases (
 tenant_id uuid NOT NULL,id uuid NOT NULL,operation_id uuid NOT NULL,
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=32768),
 binding jsonb NOT NULL CHECK(octet_length(binding::text)<=32768),
 state text NOT NULL CHECK(state IN('published','withdrawn')),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,operation_id)
);
ALTER TABLE mdm_agent_packages.releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_agent_packages.releases FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_agent_packages.releases USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT ON mdm_agent_packages.releases TO mdm_access;
GRANT SELECT,INSERT ON mdm_agent_packages.releases TO mdm_flow_runtime;
GRANT UPDATE(state) ON mdm_agent_packages.releases TO mdm_flow_runtime;
GRANT USAGE ON SCHEMA mdm_software TO mdm_access;
GRANT SELECT ON mdm_software.sources,mdm_software.versions TO mdm_access;
COMMIT;
