CREATE SCHEMA mdm_resource_catalog;
REVOKE ALL ON SCHEMA mdm_resource_catalog FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_resource_catalog TO mdm_flow_runtime;
CREATE TABLE mdm_resource_catalog.operations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=8388608), PRIMARY KEY(tenant_id,id)
);
ALTER TABLE mdm_resource_catalog.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_resource_catalog.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_resource_catalog.operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_resource_catalog.operations TO mdm_flow_runtime;
