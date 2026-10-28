BEGIN;
CREATE TABLE mdm_commands.device_source_dispatch (
 tenant_id uuid PRIMARY KEY,
 consumed bigint NOT NULL DEFAULT 0 CHECK(consumed>=0),
 watermark bigint NOT NULL DEFAULT 0 CHECK(watermark>=consumed),
 cursor text COLLATE "C",
 failure text CHECK(failure='automation_suspended'),
 failure_generation bigint NOT NULL DEFAULT 0 CHECK(failure_generation>=0)
);
ALTER TABLE mdm_commands.device_source_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_commands.device_source_dispatch FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_commands.device_source_dispatch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_commands.device_source_dispatch TO mdm_flow_runtime;
GRANT UPDATE(consumed,watermark,cursor,failure,failure_generation) ON mdm_commands.device_source_dispatch TO mdm_flow_runtime;
COMMIT;
