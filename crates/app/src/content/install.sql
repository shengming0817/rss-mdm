CREATE SCHEMA mdm_content;
REVOKE ALL ON SCHEMA mdm_content FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_content TO mdm_flow_runtime;
CREATE TABLE mdm_content.bindings (
 tenant_id uuid NOT NULL, operation uuid NOT NULL, resource text NOT NULL, version text NOT NULL,
 reference text NOT NULL, length bigint NOT NULL CHECK(length>0), sha256 bytea NOT NULL CHECK(octet_length(sha256)=32),
 PRIMARY KEY(tenant_id,operation)
);
ALTER TABLE mdm_content.bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_content.bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_content.bindings USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_content.bindings TO mdm_flow_runtime;
