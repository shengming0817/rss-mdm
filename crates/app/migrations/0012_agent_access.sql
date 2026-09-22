BEGIN;
-- This release is fresh-install only. The installer rejects every pre-existing shorter ledger
-- before this immutable unit is considered, so no deployed request is inferred as one channel.
ALTER TABLE mdm_access.requests
 ADD COLUMN channel text NOT NULL CHECK(channel IN ('agent','mdm'));

CREATE TABLE mdm_access.agent_bindings (
 tenant_id uuid NOT NULL, registration uuid NOT NULL,
 wire_version smallint NOT NULL CHECK(wire_version=1),
 capabilities text NOT NULL CHECK(capabilities='["inventory.basic.v1"]'),
 PRIMARY KEY(tenant_id,registration),
 FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id)
);
ALTER TABLE mdm_access.agent_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_access.agent_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_access.agent_bindings
 USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_access.agent_bindings TO mdm_access;

-- CollectionRun remains the only durable report and delivery owner. Agent input is already a
-- complete sealed report, so protocol-only columns are absent rather than represented by a
-- second queue. The wire report id is tenant-global in V1 and is the CollectionRun identity.
ALTER TABLE mdm_access.collection_runs DROP CONSTRAINT collection_runs_source_check;
DO $$ DECLARE constraint_name name; BEGIN
 SELECT conname INTO constraint_name FROM pg_constraint
 WHERE conrelid='mdm_access.collection_runs'::regclass AND contype='u'
   AND pg_get_constraintdef(oid)='UNIQUE (tenant_id, registration, source, epoch, sequence)';
 IF constraint_name IS NULL THEN RAISE EXCEPTION 'collection sequence constraint missing'; END IF;
 EXECUTE format('ALTER TABLE mdm_access.collection_runs DROP CONSTRAINT %I',constraint_name);
END $$;
ALTER TABLE mdm_access.collection_runs
 ALTER COLUMN session_id DROP NOT NULL,
 ALTER COLUMN request_message DROP NOT NULL,
 ALTER COLUMN first_command DROP NOT NULL,
 ALTER COLUMN request DROP NOT NULL;
ALTER TABLE mdm_access.collection_runs ADD CONSTRAINT collection_source_profile CHECK(
 (source='mdm.windows' AND session_id IS NOT NULL AND request_message IS NOT NULL
  AND first_command IS NOT NULL AND request IS NOT NULL)
 OR
 (source='agent.builtin' AND session_id IS NULL AND request_message IS NULL
  AND first_command IS NULL AND request IS NULL AND sealed_at IS NOT NULL
  AND result<>'pending' AND reason='complete' AND batch IS NOT NULL)
);
CREATE UNIQUE INDEX collection_windows_sequence ON mdm_access.collection_runs
 (tenant_id,registration,source,epoch,sequence) WHERE source='mdm.windows';
CREATE INDEX collection_agent_retention ON mdm_access.collection_runs
 (tenant_id,registration,source,epoch,sealed_at DESC,id DESC)
 WHERE source='agent.builtin' AND NOT delivery_pending;

-- Runtime cannot DELETE rows. This owner function can only prune delivered Agent reports beyond
-- the fixed retention window in the caller's tenant and exact registration epoch.
CREATE FUNCTION mdm_access.prune_agent_collections(p_registration uuid,p_epoch uuid)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE removed bigint;
BEGIN
 DELETE FROM mdm_access.collection_runs r
 WHERE r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
   AND r.registration=p_registration AND r.source='agent.builtin' AND r.epoch=p_epoch
   AND NOT r.delivery_pending AND r.id IN (
    SELECT id FROM mdm_access.collection_runs
    WHERE tenant_id=r.tenant_id AND registration=p_registration
      AND source='agent.builtin' AND epoch=p_epoch AND NOT delivery_pending
    ORDER BY sealed_at DESC,id DESC OFFSET 224
   );
 GET DIAGNOSTICS removed = ROW_COUNT;
 RETURN removed;
END $$;
REVOKE ALL ON FUNCTION mdm_access.prune_agent_collections(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_access.prune_agent_collections(uuid,uuid) TO mdm_access;

ALTER TABLE mdm_access.audit DROP CONSTRAINT audit_action_check;
ALTER TABLE mdm_access.audit ADD CONSTRAINT audit_action_check CHECK(action IN
('grant_issue','grant_revoke','registration_accept','inventory_read','device_action','authentication',
'protected_request','registration_bind','credential_revoke','device_report','enrollment_create','enrollment_resume','enrollment_cancel','enrollment_issue','enrollment_read','registration_read','windows_discovery','windows_policy','windows_management','collection_read','collection_finish','software_binding','software_candidate','software_validate','software_approve','software_authorize','software_call','software_preflight','software_result','software_withdraw','software_archive','management_read','management_write','plan_preview','plan_save','authorization_write','authorization_initialize','authorization_effective_read','authorization_rules_read','authorization_groups_read','authorization_members_read','authorization_departments_read','command_accept','command_read','command_cancel','command_approve','command_dispatch','agent_registration','agent_report','agent_report_read'));
COMMIT;
