BEGIN;
CREATE SCHEMA mdm_timeline;
REVOKE ALL ON SCHEMA mdm_timeline FROM PUBLIC;
CREATE TABLE mdm_timeline.checkpoints (
 tenant_id uuid PRIMARY KEY, generation uuid NOT NULL, position bigint NOT NULL DEFAULT -1 CHECK(position>=-1),
 source_through bigint NOT NULL DEFAULT -1 CHECK(source_through>=position), healthy boolean NOT NULL DEFAULT true
);
CREATE TABLE mdm_timeline.facts (
 tenant_id uuid NOT NULL, position bigint NOT NULL CHECK(position>=0), source text NOT NULL, event_id text NOT NULL,
 recorded_at bigint NOT NULL CHECK(recorded_at>=0), instance_id uuid, operation_id uuid,
 actor text NOT NULL, action text NOT NULL, outcome text NOT NULL, devices text[] NOT NULL, operations uuid[] NOT NULL,
 document jsonb NOT NULL CHECK(octet_length(document::text)<=16384), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(tenant_id,position),UNIQUE(tenant_id,source,event_id)
);
CREATE INDEX facts_time ON mdm_timeline.facts(tenant_id,recorded_at DESC,position DESC);
CREATE INDEX facts_operation ON mdm_timeline.facts(tenant_id,operation_id,recorded_at DESC,position DESC);
CREATE INDEX facts_related_operations ON mdm_timeline.facts USING gin(operations);
CREATE INDEX facts_devices ON mdm_timeline.facts USING gin(devices);
ALTER TABLE mdm_timeline.checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_timeline.checkpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_timeline.facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_timeline.facts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_timeline.checkpoints USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_timeline.facts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON mdm_timeline.checkpoints,mdm_timeline.facts FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_timeline,mdm_planning,mdm_assets TO mdm_access;
GRANT SELECT,INSERT ON mdm_timeline.checkpoints,mdm_timeline.facts TO mdm_access;
GRANT UPDATE(position,source_through,healthy) ON mdm_timeline.checkpoints TO mdm_access;
-- Read-only correlation belongs to Flow and remains tenant-filtered by RLS.
GRANT SELECT ON mdm_commands.action_runs,mdm_assets.operations,mdm_commands.requests TO mdm_access;
COMMIT;
