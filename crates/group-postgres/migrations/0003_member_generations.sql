BEGIN;
DROP TABLE mdm_group.deltas;
DROP TABLE mdm_group.members;
DROP TABLE mdm_group.operations;
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

ALTER TABLE mdm_group.groups DROP CONSTRAINT groups_member_count_check;
ALTER TABLE mdm_group.groups ADD CONSTRAINT groups_member_count_check CHECK(member_count BETWEEN 0 AND 1000000);
ALTER TABLE mdm_group.groups ADD COLUMN member_set uuid;
CREATE TABLE mdm_group.member_runs (
 tenant_id uuid NOT NULL, id uuid NOT NULL, group_id uuid NOT NULL,
 base_revision bigint NOT NULL CHECK(base_revision>0), rule_version text,
 input_version text NOT NULL CHECK(octet_length(input_version) BETWEEN 1 AND 4096),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 input bytea NOT NULL CHECK(octet_length(input)<=16777216),
 phase text NOT NULL CHECK(phase IN ('reading','diff','ready','published','superseded')),
 cursor text, diff_cursor text,
 object_count bigint NOT NULL DEFAULT 0 CHECK(object_count BETWEEN 0 AND 1000000),
 member_count bigint NOT NULL DEFAULT 0 CHECK(member_count BETWEEN 0 AND object_count),
 added bigint NOT NULL DEFAULT 0 CHECK(added>=0), removed bigint NOT NULL DEFAULT 0 CHECK(removed>=0),
 as_of bigint NOT NULL CHECK(as_of>=0), receipt bytea,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,group_id,id),
 FOREIGN KEY(tenant_id,group_id) REFERENCES mdm_group.groups(tenant_id,id),
 CHECK((phase='published')=(receipt IS NOT NULL))
);
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
GRANT UPDATE(phase,cursor,diff_cursor,object_count,member_count,added,removed,receipt) ON mdm_group.member_runs TO mdm_group_runtime;
GRANT UPDATE(member_set) ON mdm_group.groups TO mdm_group_runtime;
COMMIT;
