-- Current software interpretation and disposable results; no copy of the source inventory.
BEGIN;
CREATE TABLE mdm_assets.software_heads (
 tenant_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision>0)
);
CREATE TABLE mdm_assets.software_records (
 tenant_id uuid NOT NULL, kind text NOT NULL CHECK(kind IN('standard','mapping')),
 id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 document jsonb CHECK(octet_length(document::text)<=65536),
 PRIMARY KEY(tenant_id,kind,id)
);
CREATE TABLE mdm_assets.software_progress (
 tenant_id uuid NOT NULL, run uuid NOT NULL, document jsonb,
 result_state text NOT NULL DEFAULT 'retained' CHECK(result_state IN('retained','releasing','released')),
 uncertain bigint NOT NULL DEFAULT 0 CHECK(uncertain BETWEEN 0 AND 1000000),
 items bigint NOT NULL DEFAULT 0 CHECK(items BETWEEN 0 AND 10000000),
 bytes bigint NOT NULL DEFAULT 0 CHECK(bytes BETWEEN 0 AND 1073741824),
 CHECK(document IS NULL OR octet_length(document::text)<=16777216),
 PRIMARY KEY(tenant_id,run), FOREIGN KEY(tenant_id,run) REFERENCES mdm_assets.asset_query_runs(tenant_id,id)
);
CREATE TABLE mdm_assets.software_buckets (
 tenant_id uuid NOT NULL, run uuid NOT NULL, id text NOT NULL CHECK(octet_length(id)<=128),
 standard uuid, identity jsonb NOT NULL CHECK(octet_length(identity::text)<=65536),
 PRIMARY KEY(tenant_id,run,id), FOREIGN KEY(tenant_id,run) REFERENCES mdm_assets.asset_query_runs(tenant_id,id)
);
CREATE TABLE mdm_assets.software_objects (
 tenant_id uuid NOT NULL, run uuid NOT NULL, object_kind smallint NOT NULL CHECK(object_kind IN(0,1)), object_id uuid NOT NULL CHECK(object_id <> '00000000-0000-0000-0000-000000000000'::uuid),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=16777216),
 PRIMARY KEY(tenant_id,run,object_kind,object_id), FOREIGN KEY(tenant_id,run) REFERENCES mdm_assets.asset_query_runs(tenant_id,id)
);
CREATE TABLE mdm_assets.software_members (
 tenant_id uuid NOT NULL, run uuid NOT NULL, bucket text NOT NULL, object_kind smallint NOT NULL CHECK(object_kind IN(0,1)), object_id uuid NOT NULL CHECK(object_id <> '00000000-0000-0000-0000-000000000000'::uuid),
 selected boolean NOT NULL,
 compliance text NOT NULL CHECK(compliance IN('disabled','compliant','non_compliant','unknown')),
 PRIMARY KEY(tenant_id,run,bucket,object_kind,object_id),
 FOREIGN KEY(tenant_id,run,bucket) REFERENCES mdm_assets.software_buckets(tenant_id,run,id),
 FOREIGN KEY(tenant_id,run,object_kind,object_id) REFERENCES mdm_assets.software_objects(tenant_id,run,object_kind,object_id)
);
CREATE TABLE mdm_assets.software_evidence (
 tenant_id uuid NOT NULL, run uuid NOT NULL, bucket text NOT NULL, object_kind smallint NOT NULL CHECK(object_kind IN(0,1)), object_id uuid NOT NULL CHECK(object_id <> '00000000-0000-0000-0000-000000000000'::uuid),
 id text NOT NULL CHECK(octet_length(id)=64), selected boolean NOT NULL, confirmed boolean NOT NULL,
 document jsonb NOT NULL CHECK(octet_length(document::text)<=1048576),
 dimensions jsonb NOT NULL CHECK(octet_length(dimensions::text)<=65536),
 PRIMARY KEY(tenant_id,run,bucket,object_kind,object_id,id),
 FOREIGN KEY(tenant_id,run,bucket) REFERENCES mdm_assets.software_buckets(tenant_id,run,id)
);
CREATE INDEX software_members_selected ON mdm_assets.software_members(tenant_id,run,bucket,object_kind,object_id) WHERE selected;
CREATE INDEX software_evidence_object ON mdm_assets.software_evidence(tenant_id,run,object_kind,object_id,bucket COLLATE "C") WHERE confirmed;
DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['software_heads','software_records','software_progress','software_buckets','software_objects','software_members','software_evidence'] LOOP
  EXECUTE format('ALTER TABLE mdm_assets.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_assets.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_assets.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm_assets.%I FROM PUBLIC',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_assets.%I TO mdm_inventory_runtime',t);
 END LOOP;
END $$;
GRANT UPDATE(revision) ON mdm_assets.software_heads TO mdm_inventory_runtime;
GRANT UPDATE(revision,document) ON mdm_assets.software_records TO mdm_inventory_runtime;
GRANT UPDATE(document,items,bytes,uncertain,result_state) ON mdm_assets.software_progress TO mdm_inventory_runtime;
GRANT UPDATE(selected) ON mdm_assets.software_members TO mdm_inventory_runtime;
GRANT DELETE ON mdm_assets.software_evidence,mdm_assets.software_members,mdm_assets.software_objects,mdm_assets.software_buckets TO mdm_inventory_runtime;
COMMIT;
