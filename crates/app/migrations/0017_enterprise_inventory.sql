BEGIN;
ALTER TABLE mdm_access.collection_runs DROP CONSTRAINT collection_source_profile;
ALTER TABLE mdm_access.collection_runs ADD CONSTRAINT collection_source_profile CHECK(
 (source='mdm.windows' AND session_id IS NOT NULL AND request_message IS NOT NULL AND first_command IS NOT NULL AND request IS NOT NULL)
 OR (source IN ('agent.builtin','agent.script','agent.osquery') AND session_id IS NULL AND request_message IS NULL AND first_command IS NULL AND request IS NULL AND sealed_at IS NOT NULL AND result<>'pending' AND reason='complete' AND batch IS NOT NULL)
);
CREATE UNIQUE INDEX collection_enterprise_sequence ON mdm_access.collection_runs(tenant_id,registration,source,epoch,sequence) WHERE source IN ('agent.script','agent.osquery');
COMMIT;
