BEGIN;
CREATE TABLE mdm_software_deployment.device_source_dispatch (
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
ALTER TABLE mdm_software_deployment.device_source_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_software_deployment.device_source_dispatch FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_software_deployment.device_source_dispatch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_software_deployment.device_source_dispatch TO mdm_command_runtime;
GRANT UPDATE(from_cut,to_cut,event_after,page_through,cursor,relation_consumed,relation_watermark,relation_cursor,failure,failure_generation) ON mdm_software_deployment.device_source_dispatch TO mdm_command_runtime;
GRANT SELECT ON mdm.asset_changes,mdm_access.asset_authority_history TO mdm_command_runtime;
COMMIT;

-- Read-only discovery of original owner work; business execution remains fenced.
CREATE POLICY work_discovery ON mdm_software_deployment.device_source_dispatch FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_software_deployment.device_recovery FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_software_deployment.policy_recovery FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_software_deployment.action_runs FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_software_deployment.agent_install_inputs FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_software_deployment.operations FOR SELECT TO mdm_owner USING(true);
CREATE FUNCTION mdm_software_deployment.work_scopes(after_tenant uuid) RETURNS TABLE(tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT tenant_id FROM ((SELECT DISTINCT tenant_id FROM mdm_software_deployment.device_source_dispatch WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32) UNION (SELECT DISTINCT tenant_id FROM mdm_software_deployment.device_recovery WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32) UNION (SELECT DISTINCT tenant_id FROM mdm_software_deployment.policy_recovery WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32) UNION (SELECT DISTINCT tenant_id FROM mdm_software_deployment.action_runs WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32) UNION (SELECT DISTINCT tenant_id FROM mdm_software_deployment.agent_install_inputs WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32) UNION (SELECT DISTINCT tenant_id FROM mdm_devices.retirements WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32) UNION (SELECT DISTINCT tenant_id FROM mdm_policy.assignments WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32)) work ORDER BY tenant_id LIMIT 32
$$;
CREATE FUNCTION mdm_software_deployment.work_epoch(t uuid,entity text) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT min(expected_epoch) FROM (SELECT expected_epoch FROM mdm_software_deployment.device_source_dispatch WHERE tenant_id=t AND entity='inputs' UNION ALL SELECT expected_epoch FROM mdm_software_deployment.device_recovery WHERE tenant_id=t AND entity=mdm_software_deployment.recovery_key(device) UNION ALL SELECT expected_epoch FROM mdm_software_deployment.policy_recovery WHERE tenant_id=t AND entity='policy.'||policy::text UNION ALL SELECT expected_epoch FROM mdm_software_deployment.action_runs WHERE tenant_id=t AND entity='run:'||id::text UNION ALL SELECT expected_epoch FROM mdm_devices.retirements WHERE tenant_id=t AND entity='retirement:'||id::text UNION ALL SELECT expected_epoch FROM mdm_software_deployment.agent_install_inputs WHERE tenant_id=t AND entity='agent-install:'||mdm_software_deployment.recovery_key(device) UNION ALL SELECT expected_epoch FROM mdm_policy.assignments WHERE tenant_id=t AND entity='scheduled:'||version::text||':'||(target->>'device')) original WHERE expected_epoch IS NOT NULL HAVING count(DISTINCT expected_epoch)=1
$$;
CREATE FUNCTION mdm_software_deployment.work_relay_scopes(after_tenant uuid,after_epoch bigint) RETURNS TABLE(tenant_id uuid,expected_epoch bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT tenant_id,expected_epoch FROM (SELECT DISTINCT r.tenant_id,r.expected_epoch FROM mdm_software_deployment.operations r WHERE (after_tenant IS NULL OR (r.tenant_id,r.expected_epoch)>(after_tenant,after_epoch)) AND EXISTS (SELECT FROM rss_transactional_messaging.outbox o WHERE o.tenant_id=r.tenant_id AND o.domain='mdm.software.deployment.v1' AND o.message_id='dispatch.'||r.id::text AND o.status NOT IN ('published','resolved')) UNION SELECT DISTINCT r.tenant_id,r.expected_epoch FROM mdm_software_deployment.action_runs r WHERE (after_tenant IS NULL OR (r.tenant_id,r.expected_epoch)>(after_tenant,after_epoch)) AND EXISTS (SELECT FROM rss_transactional_messaging.outbox o WHERE o.tenant_id=r.tenant_id AND o.domain='mdm.software.deployment.v1' AND o.message_id='action.'||r.id::text AND o.status NOT IN ('published','resolved'))) work ORDER BY tenant_id,expected_epoch LIMIT 32
$$;
ALTER FUNCTION mdm_software_deployment.work_scopes(uuid) OWNER TO mdm_owner;
ALTER FUNCTION mdm_software_deployment.work_epoch(uuid,text) OWNER TO mdm_owner;
ALTER FUNCTION mdm_software_deployment.work_relay_scopes(uuid,bigint) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_software_deployment.work_scopes(uuid),mdm_software_deployment.work_epoch(uuid,text),mdm_software_deployment.work_relay_scopes(uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_software_deployment.work_scopes(uuid),mdm_software_deployment.work_epoch(uuid,text),mdm_software_deployment.work_relay_scopes(uuid,bigint) TO mdm_access;

CREATE FUNCTION mdm_software_deployment.artifact_scope(operation uuid) RETURNS TABLE(tenant_id uuid,expected_epoch bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT tenant_id,expected_epoch FROM mdm_software_deployment.operations WHERE id=operation ORDER BY tenant_id LIMIT 2
$$;
REVOKE ALL ON FUNCTION mdm_software_deployment.artifact_scope(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_software_deployment.artifact_scope(uuid) TO mdm_access;
