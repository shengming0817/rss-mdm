BEGIN;
CREATE TABLE mdm_planning.configuration_source_dispatch (
 expected_epoch bigint NOT NULL CHECK(expected_epoch>0),
 tenant_id uuid PRIMARY KEY,
 from_cut jsonb, to_cut jsonb,
 event_after bigint NOT NULL DEFAULT 0 CHECK(event_after>=0),
 page_through bigint CHECK(page_through>event_after),
 cursor uuid,
 relation_consumed bigint NOT NULL DEFAULT 0 CHECK(relation_consumed>=0),
 relation_watermark bigint NOT NULL DEFAULT 0 CHECK(relation_watermark>=relation_consumed),
 relation_cursor bigint CHECK(relation_cursor>=relation_consumed),
 failure text CHECK(failure='automation_suspended'),
 failure_generation bigint NOT NULL DEFAULT 0 CHECK(failure_generation>=0)
);
ALTER TABLE mdm_planning.configuration_source_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.configuration_source_dispatch FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_planning.configuration_source_dispatch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_planning.configuration_source_dispatch TO mdm_policy_runtime;
GRANT UPDATE(from_cut,to_cut,event_after,page_through,cursor,relation_consumed,relation_watermark,relation_cursor,failure,failure_generation) ON mdm_planning.configuration_source_dispatch TO mdm_policy_runtime;
GRANT SELECT ON mdm.asset_changes,mdm_access.asset_authority_history TO mdm_policy_runtime;
COMMIT;

CREATE POLICY work_discovery ON mdm_planning.configuration_source_dispatch FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_planning.configuration_devices FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_planning.configuration_operations FOR SELECT TO mdm_owner USING(true);
CREATE FUNCTION mdm_planning.configuration_work_scopes(after_tenant uuid) RETURNS TABLE(tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT tenant_id FROM (SELECT tenant_id FROM mdm_planning.configuration_source_dispatch UNION SELECT tenant_id FROM mdm_planning.configuration_devices) work
 WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32
$$;
CREATE FUNCTION mdm_planning.configuration_work_epoch(t uuid, entity text) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT expected_epoch FROM mdm_planning.configuration_source_dispatch WHERE tenant_id=t AND entity='configuration-inputs'
 UNION ALL SELECT expected_epoch FROM mdm_planning.configuration_devices WHERE tenant_id=t AND entity='configuration:'||mdm_planning.configuration_device_key(device)
$$;
CREATE FUNCTION mdm_planning.configuration_relay_scopes(after_tenant uuid, after_epoch bigint) RETURNS TABLE(tenant_id uuid, expected_epoch bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT DISTINCT tenant_id,expected_epoch FROM mdm_planning.configuration_operations WHERE after_tenant IS NULL OR (tenant_id,expected_epoch)>(after_tenant,after_epoch)
 ORDER BY tenant_id,expected_epoch LIMIT 32
$$;
ALTER FUNCTION mdm_planning.configuration_work_scopes(uuid) OWNER TO mdm_owner;
ALTER FUNCTION mdm_planning.configuration_work_epoch(uuid,text) OWNER TO mdm_owner;
ALTER FUNCTION mdm_planning.configuration_relay_scopes(uuid,bigint) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_planning.configuration_work_scopes(uuid),mdm_planning.configuration_work_epoch(uuid,text),mdm_planning.configuration_relay_scopes(uuid,bigint) FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_planning TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_planning.configuration_work_scopes(uuid),mdm_planning.configuration_work_epoch(uuid,text),mdm_planning.configuration_relay_scopes(uuid,bigint) TO mdm_access;
