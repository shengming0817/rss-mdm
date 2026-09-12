-- Install once as the external schema owner, after RSS transactional messaging.
CREATE SCHEMA mdm_group;
REVOKE ALL ON SCHEMA mdm_group FROM PUBLIC;
CREATE TABLE mdm_group.groups (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL CHECK(id <> '00000000-0000-0000-0000-000000000000'),
 kind text NOT NULL CHECK(kind IN ('static','dynamic')),
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 4096),
 description text NOT NULL CHECK(octet_length(description)<=4096),
 revision bigint NOT NULL CHECK(revision>0),
 member_version bigint NOT NULL CHECK(member_version>=0 AND member_version<=revision),
 member_count bigint NOT NULL CHECK(member_count BETWEEN 0 AND 10000),
 rule_version text CHECK(octet_length(rule_version) BETWEEN 1 AND 256),
 deleted boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id),
 CHECK((kind='static' AND rule_version IS NULL) OR (kind='dynamic' AND rule_version IS NOT NULL))
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
CREATE TABLE mdm_group.members (
 tenant_id uuid NOT NULL, group_id uuid NOT NULL,
 object_id text NOT NULL CHECK(octet_length(object_id) BETWEEN 1 AND 4096),
 -- Hash index avoids PostgreSQL's per-index-item limit for core-valid 4 KiB UTF-8 IDs.
 object_digest bytea NOT NULL CHECK(octet_length(object_digest)=32),
 PRIMARY KEY(tenant_id,group_id,object_digest),
 FOREIGN KEY(tenant_id,group_id) REFERENCES mdm_group.groups(tenant_id,id)
);
CREATE TABLE mdm_group.operations (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL CHECK(id <> '00000000-0000-0000-0000-000000000000'),
 group_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('command','recalculation')),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 request bytea NOT NULL CHECK(octet_length(request) BETWEEN 1 AND 67108864),
 trigger bytea CHECK(octet_length(trigger) BETWEEN 1 AND 16384),
 state text NOT NULL CHECK(state IN ('pending','completed','rejected')),
 receipt bytea CHECK(octet_length(receipt) BETWEEN 1 AND 65536),
 result bytea CHECK(octet_length(result)<=67108864),
 result_digest bytea CHECK(octet_length(result_digest)=32),
 failure text,
 base_revision bigint NOT NULL CHECK(base_revision>=0),
 rule_version text,
 as_of bigint NOT NULL CHECK(as_of>=0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,group_id) REFERENCES mdm_group.groups(tenant_id,id),
 FOREIGN KEY(tenant_id,group_id,rule_version) REFERENCES mdm_group.rules(tenant_id,group_id,version),
 CHECK((state='pending' AND receipt IS NULL AND failure IS NULL AND completed_at IS NULL)
    OR (state='completed' AND receipt IS NOT NULL AND failure IS NULL AND completed_at IS NOT NULL)
    OR (state='rejected' AND receipt IS NULL AND failure IS NOT NULL AND completed_at IS NOT NULL)),
 CHECK((result IS NULL)=(result_digest IS NULL)),
 CHECK((kind='command' AND state='completed' AND trigger IS NULL AND result IS NULL)
    OR (kind='recalculation' AND trigger IS NOT NULL AND rule_version IS NOT NULL AND base_revision>0
      AND ((state='completed' AND result IS NOT NULL) OR (state<>'completed' AND result IS NULL))))
);
CREATE INDEX recoverable ON mdm_group.operations(tenant_id,id) WHERE state='pending';
CREATE TABLE mdm_group.deltas (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL,
 object_id text NOT NULL CHECK(octet_length(object_id) BETWEEN 1 AND 4096),
 object_digest bytea NOT NULL CHECK(octet_length(object_digest)=32),
 added boolean NOT NULL,
 PRIMARY KEY(tenant_id,operation_id,object_digest),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES mdm_group.operations(tenant_id,id)
);
DO $ddl$
DECLARE t text;
BEGIN
 FOR t IN SELECT unnest(ARRAY['groups','rules','members','operations','deltas']) LOOP
  EXECUTE format('ALTER TABLE mdm_group.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE mdm_group.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON mdm_group.%I USING (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
  EXECUTE format('REVOKE ALL ON mdm_group.%I FROM PUBLIC',t);
 END LOOP;
END $ddl$;
GRANT USAGE ON SCHEMA mdm_group TO mdm_group_runtime;
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA mdm_group TO mdm_group_runtime;
GRANT UPDATE(name,description,revision,member_version,member_count,rule_version,deleted) ON mdm_group.groups TO mdm_group_runtime;
GRANT UPDATE(state,receipt,result,result_digest,failure,completed_at) ON mdm_group.operations TO mdm_group_runtime;
GRANT DELETE ON mdm_group.members TO mdm_group_runtime;
