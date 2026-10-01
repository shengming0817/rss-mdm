CREATE SCHEMA mdm_software;
REVOKE ALL ON SCHEMA mdm_software FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_software TO mdm_flow_runtime;
CREATE TABLE mdm_software.sources (
 tenant_id uuid NOT NULL,id text NOT NULL,revision text NOT NULL,
 definition jsonb NOT NULL CHECK(octet_length(definition::text)<=65536),
 admission jsonb NOT NULL CHECK(octet_length(admission::text)<=65536),PRIMARY KEY(tenant_id,id,revision)
);
CREATE TABLE mdm_software.approvals (
 tenant_id uuid NOT NULL,resource text NOT NULL,version text NOT NULL,
 admission jsonb NOT NULL CHECK(octet_length(admission::text)<=65536),PRIMARY KEY(tenant_id,resource,version)
);
CREATE TABLE mdm_software.operations (
 tenant_id uuid NOT NULL,id uuid NOT NULL,fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=1048576),PRIMARY KEY(tenant_id,id)
);
CREATE TABLE mdm_software.materials (
 tenant_id uuid NOT NULL,coordinate bytea NOT NULL CHECK(octet_length(coordinate)=32),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),PRIMARY KEY(tenant_id,coordinate)
);
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['sources','approvals','operations','materials'] LOOP
 EXECUTE format('ALTER TABLE mdm_software.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_software.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_software.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 EXECUTE format('GRANT SELECT,INSERT ON mdm_software.%I TO mdm_flow_runtime',t);
END LOOP; END $$;
GRANT UPDATE(admission) ON mdm_software.sources,mdm_software.approvals TO mdm_flow_runtime;

GRANT USAGE ON SCHEMA mdm_software TO mdm_software_driver;
GRANT SELECT ON mdm_software.sources,mdm_software.approvals TO mdm_software_driver;
