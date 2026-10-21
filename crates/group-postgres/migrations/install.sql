-- Install once as the external schema owner, after RSS transactional messaging.
CREATE SCHEMA mdm_group;
REVOKE ALL ON SCHEMA mdm_group FROM PUBLIC;
CREATE TABLE mdm_group.groups (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL CHECK(id <> '00000000-0000-0000-0000-000000000000'),
 kind text NOT NULL CHECK(kind IN ('static','dynamic','system')),
 system_selector text CHECK(system_selector IN ('all_active','windows','macos')),
 CONSTRAINT groups_system_selector_check CHECK((kind='system')=(system_selector IS NOT NULL)),
 UNIQUE(tenant_id,system_selector),
 presentation jsonb NOT NULL CHECK(jsonb_typeof(presentation)='object' AND presentation ?& ARRAY['name','description'] AND octet_length(presentation::text)<=131072
   AND jsonb_typeof(presentation->'name')='string' AND octet_length(presentation->>'name') BETWEEN 1 AND 4096
   AND jsonb_typeof(presentation->'description')='string' AND octet_length(presentation->>'description')<=4096),
 revision bigint NOT NULL CHECK(revision>0),
 calculation_revision bigint NOT NULL DEFAULT 0 CHECK(calculation_revision>=0),
 member_version bigint NOT NULL CHECK(member_version>=0 AND member_version<=calculation_revision),
 member_count bigint NOT NULL CHECK(member_count BETWEEN 0 AND 1000000),
 member_set uuid,
 rule_version text CHECK(octet_length(rule_version) BETWEEN 1 AND 256),
 deleted boolean NOT NULL DEFAULT false,
 asset_context text NOT NULL CONSTRAINT groups_asset_context_check CHECK(asset_context IN ('endpoint','associated_device')),
 CONSTRAINT groups_context_kind_check CHECK(kind='dynamic' OR asset_context='endpoint'),
 PRIMARY KEY(tenant_id,id),
 CHECK((kind IN ('static','system') AND rule_version IS NULL) OR (kind='dynamic' AND rule_version IS NOT NULL))
);
CREATE TABLE mdm_group.rules (
 tenant_id uuid NOT NULL, group_id uuid NOT NULL,
 version text NOT NULL CHECK(octet_length(version) BETWEEN 1 AND 256),
 document bytea NOT NULL CHECK(octet_length(document) BETWEEN 1 AND 67108864),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,group_id,version),
 FOREIGN KEY(tenant_id,group_id) REFERENCES mdm_group.groups(tenant_id,id)
);
ALTER TABLE mdm_group.groups ADD FOREIGN KEY(tenant_id,id,rule_version)
 REFERENCES mdm_group.rules(tenant_id,group_id,version) DEFERRABLE INITIALLY DEFERRED;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['groups','rules'] LOOP
  EXECUTE format('ALTER TABLE mdm_group.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_group.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_group.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm_group.%I FROM PUBLIC',t);
 END LOOP;
END $$;
GRANT USAGE ON SCHEMA mdm_group TO mdm_group_runtime;
GRANT SELECT,INSERT ON mdm_group.groups,mdm_group.rules TO mdm_group_runtime;
GRANT UPDATE(presentation,revision,member_version,member_count,rule_version,deleted,calculation_revision) ON mdm_group.groups TO mdm_group_runtime;

CREATE TABLE mdm_group.operations (
 tenant_id uuid NOT NULL,id uuid NOT NULL,group_id uuid NOT NULL,digest bytea NOT NULL CHECK(octet_length(digest)=32),
 request bytea NOT NULL CHECK(octet_length(request)<=16777216),receipt bytea NOT NULL CHECK(octet_length(receipt)<=65536),
 receipt_digest bytea NOT NULL CHECK(octet_length(receipt_digest)=32),as_of bigint NOT NULL CHECK(as_of>=0),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,group_id) REFERENCES mdm_group.groups(tenant_id,id)
);
ALTER TABLE mdm_group.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_group.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_group.operations USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_group.operations TO mdm_group_runtime;

CREATE TABLE mdm_group.member_runs (
 tenant_id uuid NOT NULL, id uuid NOT NULL, group_id uuid NOT NULL,
 base_revision bigint NOT NULL CHECK(base_revision>0), base_calculation bigint NOT NULL CHECK(base_calculation>=0), floor_revision bigint NOT NULL CHECK(floor_revision>=0), rule_version text,
 input_version text NOT NULL CHECK(octet_length(input_version) BETWEEN 1 AND 4096),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 input bytea NOT NULL CHECK(octet_length(input)<=16777216),
 phase text NOT NULL CHECK(phase IN ('reading','diff','ready','published','superseded')),
 cursor text, diff_cursor text,
 processed_count bigint NOT NULL DEFAULT 0 CHECK(processed_count BETWEEN 0 AND 1000000),
 object_count bigint NOT NULL DEFAULT 0 CHECK(object_count BETWEEN 0 AND 1000000),
 member_count bigint NOT NULL DEFAULT 0 CHECK(member_count BETWEEN 0 AND 1000000),
 added bigint NOT NULL DEFAULT 0 CHECK(added>=0), removed bigint NOT NULL DEFAULT 0 CHECK(removed>=0),
 as_of bigint NOT NULL CHECK(as_of>=0), receipt bytea,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,group_id,id),
 FOREIGN KEY(tenant_id,group_id) REFERENCES mdm_group.groups(tenant_id,id),
 CHECK((phase='published')=(receipt IS NOT NULL))
);
CREATE INDEX member_runs_history ON mdm_group.member_runs(tenant_id,group_id,base_calculation) WHERE phase='published';
ALTER TABLE mdm_group.groups ADD FOREIGN KEY(tenant_id,id,member_set)
 REFERENCES mdm_group.member_runs(tenant_id,group_id,id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE mdm_group.member_rows (
 tenant_id uuid NOT NULL, run_id uuid NOT NULL,
 object_id text COLLATE "C" NOT NULL CHECK(octet_length(object_id) BETWEEN 1 AND 256),
 matched boolean NOT NULL, evidence bytea NOT NULL CHECK(octet_length(evidence)<=1048576),
 evidence_digest bytea NOT NULL CHECK(octet_length(evidence_digest)=32),
 PRIMARY KEY(tenant_id,run_id,object_id),
 FOREIGN KEY(tenant_id,run_id) REFERENCES mdm_group.member_runs(tenant_id,id)
);
CREATE INDEX member_rows_matched ON mdm_group.member_rows(tenant_id,run_id,object_id) WHERE matched;
CREATE TABLE mdm_group.member_pages (
 tenant_id uuid NOT NULL, run_id uuid NOT NULL, first_id text COLLATE "C" NOT NULL,
 last_id text COLLATE "C" NOT NULL, fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(tenant_id,run_id,first_id),
 FOREIGN KEY(tenant_id,run_id) REFERENCES mdm_group.member_runs(tenant_id,id)
);
CREATE TABLE mdm_group.member_changes (
 tenant_id uuid NOT NULL, run_id uuid NOT NULL, object_id text COLLATE "C" NOT NULL,
 group_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 added boolean NOT NULL, PRIMARY KEY(tenant_id,run_id,object_id),
 FOREIGN KEY(tenant_id,run_id) REFERENCES mdm_group.member_runs(tenant_id,id)
);
CREATE INDEX member_changes_history ON mdm_group.member_changes(tenant_id,group_id,object_id,revision DESC);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['member_runs','member_rows','member_pages','member_changes'] LOOP
  EXECUTE format('ALTER TABLE mdm_group.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_group.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_group.%I USING(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm_group.%I FROM PUBLIC',t);
  EXECUTE format('GRANT SELECT,INSERT ON mdm_group.%I TO mdm_group_runtime',t);
 END LOOP;
END $$;
GRANT UPDATE(phase,cursor,diff_cursor,object_count,processed_count,member_count,added,removed,receipt) ON mdm_group.member_runs TO mdm_group_runtime;
GRANT UPDATE(member_set) ON mdm_group.groups TO mdm_group_runtime;


CREATE INDEX member_changes_object ON mdm_group.member_changes(tenant_id,object_id,group_id,revision DESC);
CREATE INDEX groups_dynamic ON mdm_group.groups(tenant_id,id) WHERE kind IN ('dynamic','system') AND NOT deleted;
