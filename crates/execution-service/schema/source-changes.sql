BEGIN;
CREATE TABLE mdm_commands.device_source_dispatch (
 tenant_id uuid PRIMARY KEY,
 consumed bigint NOT NULL DEFAULT 0 CHECK(consumed>=0),
 watermark bigint NOT NULL DEFAULT 0 CHECK(watermark>=consumed),
 cursor text COLLATE "C",
 relation_consumed bigint NOT NULL DEFAULT 0 CHECK(relation_consumed>=0),
 relation_watermark bigint NOT NULL DEFAULT 0 CHECK(relation_watermark>=relation_consumed),
 relation_cursor bigint CHECK(relation_cursor>=relation_consumed),
 failure text CHECK(failure='automation_suspended'),
 failure_generation bigint NOT NULL DEFAULT 0 CHECK(failure_generation>=0)
);
ALTER TABLE mdm_commands.device_source_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_commands.device_source_dispatch FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_commands.device_source_dispatch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_commands.device_source_dispatch TO mdm_command_runtime;
GRANT UPDATE(consumed,watermark,cursor,relation_consumed,relation_watermark,relation_cursor,failure,failure_generation) ON mdm_commands.device_source_dispatch TO mdm_command_runtime;
GRANT SELECT ON mdm.asset_changes,mdm_access.asset_authority_history TO mdm_command_runtime;
COMMIT;
