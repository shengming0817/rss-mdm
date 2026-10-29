CREATE SCHEMA mdm_software_snapshots;
REVOKE ALL ON SCHEMA mdm_software_snapshots FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_software_snapshots TO mdm_flow_runtime;
CREATE TABLE mdm_software_snapshots.current (
 tenant_id uuid NOT NULL,source text NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 document text NOT NULL CHECK(octet_length(document)<=67108864),document_sha256 bytea NOT NULL CHECK(octet_length(document_sha256)=32),
 extraction jsonb NOT NULL CHECK(octet_length(extraction::text)<=32768),
 entry_count bigint NOT NULL CHECK(entry_count BETWEEN 0 AND 100000),imported_at bigint NOT NULL,
 PRIMARY KEY(tenant_id,source)
);
CREATE TABLE mdm_software_snapshots.entries (
 tenant_id uuid NOT NULL,source text NOT NULL,id uuid NOT NULL,
 byte_offset bigint NOT NULL CHECK(byte_offset>=0),byte_length bigint NOT NULL CHECK(byte_length>0),
 package_id text,name text,version text,
 PRIMARY KEY(tenant_id,source,id),
 FOREIGN KEY(tenant_id,source) REFERENCES mdm_software_snapshots.current(tenant_id,source)
);
CREATE TABLE mdm_software_snapshots.operations (
 tenant_id uuid NOT NULL,source text NOT NULL,id uuid NOT NULL,actor text NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 response jsonb NOT NULL CHECK(octet_length(response::text)<=65536),
 PRIMARY KEY(tenant_id,source,id)
);
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['current','entries','operations'] LOOP
 EXECUTE format('ALTER TABLE mdm_software_snapshots.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE mdm_software_snapshots.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON mdm_software_snapshots.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 EXECUTE format('GRANT SELECT,INSERT ON mdm_software_snapshots.%I TO mdm_flow_runtime',t);
END LOOP; END $$;
GRANT UPDATE(revision,document,document_sha256,extraction,entry_count,imported_at) ON mdm_software_snapshots.current TO mdm_flow_runtime;
GRANT DELETE ON mdm_software_snapshots.entries TO mdm_flow_runtime;
