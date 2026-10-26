BEGIN;
CREATE SCHEMA mdm_timeline;
REVOKE ALL ON SCHEMA mdm_timeline FROM PUBLIC;
CREATE TABLE mdm_timeline.facts (
 tenant_id uuid NOT NULL, position bigint NOT NULL CHECK(position>=0), source text NOT NULL, event_id text NOT NULL,
 recorded_at bigint NOT NULL CHECK(recorded_at>=0), instance_id uuid, operation_id uuid,
 actor text NOT NULL, action text NOT NULL, outcome text NOT NULL, devices text[] NOT NULL, operations uuid[] NOT NULL,
 activity jsonb CHECK(octet_length(activity::text)<=16384),
 activity_digest bytea CHECK(activity_digest IS NULL OR octet_length(activity_digest)=32),
 CHECK((activity IS NULL)=(activity_digest IS NULL)),
 document jsonb NOT NULL CHECK(octet_length(document::text)<=16384), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,position),UNIQUE(tenant_id,source,event_id)
);
CREATE INDEX facts_time ON mdm_timeline.facts(tenant_id,recorded_at DESC,position DESC);
CREATE INDEX facts_target ON mdm_timeline.facts(tenant_id,(document->'target'->>'type'),(document->'target'->>'id'),recorded_at DESC,position DESC);
CREATE INDEX facts_operation ON mdm_timeline.facts(tenant_id,operation_id,recorded_at DESC,position DESC);
CREATE INDEX facts_related_operations ON mdm_timeline.facts USING gin(operations);
CREATE INDEX facts_devices ON mdm_timeline.facts USING gin(devices);
ALTER TABLE mdm_timeline.facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_timeline.facts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_timeline.facts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_timeline.facts FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_timeline.facts TO mdm_access;
GRANT USAGE ON SCHEMA mdm_timeline,mdm_planning,mdm_assets TO mdm_access;
-- Read-only correlation belongs to Flow and remains tenant-filtered by RLS.
GRANT SELECT ON mdm_commands.action_runs,mdm_assets.operations,mdm_commands.requests,mdm_commands.operations,mdm_policy.versions TO mdm_access;
CREATE TABLE mdm_timeline.activity_streams (
 tenant_id uuid NOT NULL, device text NOT NULL, generation uuid NOT NULL, revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 PRIMARY KEY(tenant_id,device)
);
CREATE TABLE mdm_timeline.activity_entries (
 tenant_id uuid NOT NULL, device text NOT NULL, revision bigint NOT NULL CHECK(revision>0), position bigint NOT NULL,
 PRIMARY KEY(tenant_id,device,revision),UNIQUE(tenant_id,device,position),
 FOREIGN KEY(tenant_id,position) REFERENCES mdm_timeline.facts(tenant_id,position)
);
ALTER TABLE mdm_timeline.activity_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_timeline.activity_streams FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_timeline.activity_streams USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_timeline.activity_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_timeline.activity_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_timeline.activity_entries USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_timeline.activity_streams,mdm_timeline.activity_entries FROM PUBLIC;
GRANT SELECT,INSERT ON mdm_timeline.activity_streams,mdm_timeline.activity_entries TO mdm_access;
GRANT UPDATE(revision) ON mdm_timeline.activity_streams TO mdm_access;
COMMIT;
