-- #2554: current-format installation only; no reader or converter for old deployments.
BEGIN;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM mdm.inventory) OR EXISTS(SELECT 1 FROM mdm.manual_assignments) THEN
  RAISE EXCEPTION 'fresh unified inventory installation required';
 END IF;
END $$;
ALTER TABLE mdm.inventory ADD COLUMN collection_sequence bigint NOT NULL CHECK(collection_sequence>=0);
ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_field_check;
ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_field_check CHECK(length(field)<=128 AND field ~ '^(device|custom|channel)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$');
ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_value_check;
ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_value_check CHECK(octet_length(value) BETWEEN 1 AND 16777216);
ALTER TABLE mdm.inventory DROP CONSTRAINT inventory_state_check;
ALTER TABLE mdm.inventory ADD CONSTRAINT inventory_state_check CHECK(state IN ('known','null','deleted','unsupported'));
ALTER TABLE mdm.manual_assignments DROP CONSTRAINT manual_assignments_field_check;
ALTER TABLE mdm.manual_assignments ADD CONSTRAINT manual_assignments_field_check CHECK(length(field)<=128 AND field ~ '^custom\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$');
ALTER TABLE mdm.manual_assignments DROP CONSTRAINT manual_assignments_fact_check;
ALTER TABLE mdm.manual_assignments ADD CONSTRAINT manual_assignments_fact_check CHECK(octet_length(fact::text)<=16777216);
ALTER TABLE mdm.inventory_history DROP CONSTRAINT inventory_history_document_check;
ALTER TABLE mdm.inventory_history ADD CONSTRAINT inventory_history_document_check CHECK(document IS NULL OR octet_length(document::text)<=33554432);
ALTER TABLE mdm.manual_history DROP CONSTRAINT manual_history_document_check;
ALTER TABLE mdm.manual_history ADD CONSTRAINT manual_history_document_check CHECK(document IS NULL OR octet_length(document::text)<=33554432);
ALTER TABLE mdm.asset_changes DROP CONSTRAINT asset_changes_kind_check;
ALTER TABLE mdm.asset_changes ADD CONSTRAINT asset_changes_kind_check CHECK(kind IN ('inventory','manual','device','registration','source','credential','catalog'));
CREATE TABLE mdm.field_versions (
 tenant_id uuid NOT NULL, field text NOT NULL, version bigint NOT NULL CHECK(version>0),
 revision bigint NOT NULL, definition jsonb,
 PRIMARY KEY(tenant_id,field,version),
 FOREIGN KEY(tenant_id,revision) REFERENCES mdm.asset_changes(tenant_id,revision),
 CHECK(definition IS NULL OR octet_length(definition::text)<=65536)
);
CREATE INDEX field_versions_watermark ON mdm.field_versions(tenant_id,revision,field);
CREATE TABLE mdm.collection_definitions (
 tenant_id uuid NOT NULL, dataset text NOT NULL, version text NOT NULL CHECK(length(version) BETWEEN 1 AND 128),
 source text NOT NULL CHECK(source IN ('mdm.windows','mdm.apple','agent.builtin','agent.script','agent.osquery')),
 fingerprint text NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 coverage text NOT NULL, definition jsonb NOT NULL CHECK(octet_length(definition::text)<=1048576),
 PRIMARY KEY(tenant_id,dataset,source,version), UNIQUE(tenant_id,coverage,source)
);
CREATE TABLE mdm.collection_results (
 tenant_id uuid NOT NULL,run text NOT NULL CHECK(length(run) BETWEEN 1 AND 256),
 scope text NOT NULL,coverage text NOT NULL,sequence bigint NOT NULL CHECK(sequence>=0),
 observed_at bigint NOT NULL,digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 document bytea NOT NULL CHECK(octet_length(document)<=33554432),
 PRIMARY KEY(tenant_id,run)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['field_versions','collection_definitions','collection_results'] LOOP
  EXECUTE format('ALTER TABLE mdm.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm.%I FROM PUBLIC',t);
 END LOOP;
END $$;
GRANT SELECT ON mdm.field_versions,mdm.collection_definitions,mdm.collection_results TO mdm_runtime;
GRANT SELECT ON mdm.field_versions,mdm.collection_definitions TO mdm_api;
COMMIT;
