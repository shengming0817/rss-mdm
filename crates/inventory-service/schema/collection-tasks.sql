-- Stable collection admission/dispatch. Per-attempt reports remain in collection_runs.
BEGIN;
CREATE TABLE mdm_inventory.collection_tasks (expected_epoch bigint NOT NULL CHECK(expected_epoch>0),tenant_id uuid NOT NULL, id uuid NOT NULL, policy_version uuid NOT NULL, channel text NOT NULL CHECK (channel IN ('agent', 'mdm')), origin jsonb NOT NULL CHECK (origin IN ('"system"', '"policy"', '"human"', '"ai"')), source_objects jsonb NOT NULL, device uuid NOT NULL, occurrence text NOT NULL CHECK (octet_length(occurrence) BETWEEN 1 AND 256), triggered_at bigint CHECK (triggered_at IS NULL OR triggered_at >= 0), created_at bigint NOT NULL CHECK (created_at >= 0), available_at bigint NOT NULL CHECK (available_at >= 0), deadline bigint NOT NULL CHECK (deadline > available_at), gateway_accepted boolean NOT NULL DEFAULT FALSE, dispatch_fingerprint bytea NOT NULL CHECK (octet_length(dispatch_fingerprint) = 32), dispatch_failure jsonb CHECK (dispatch_failure IS NULL OR octet_length(CAST(dispatch_failure AS text)) <= 8192), agent_state jsonb CHECK (agent_state IS NULL OR octet_length(CAST(agent_state AS text)) <= 4096), agent_result jsonb CHECK (agent_result IS NULL OR octet_length(CAST(agent_result AS text)) <= 1114112), native_delivery text CHECK (native_delivery IN ('queued', 'prepared', 'sent', 'cancelled')), collection_run uuid, terminal_notified boolean NOT NULL DEFAULT FALSE, started_at bigint CHECK (started_at IS NULL OR started_at >= 0), CHECK (NOT terminal_notified OR (channel = 'mdm' AND collection_run IS NOT NULL)), CHECK ((channel = 'agent' AND agent_state IS NOT NULL AND native_delivery IS NULL AND collection_run IS NULL AND started_at IS NULL) OR (channel = 'mdm' AND agent_state IS NULL AND agent_result IS NULL AND native_delivery IS NOT NULL)), PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, policy_version, device, occurrence));
CREATE TABLE mdm_inventory.collection_admission (
    tenant_id uuid NOT NULL
  , device uuid NOT NULL
  , policy_after uuid
  , PRIMARY KEY (tenant_id, device)
);
CREATE TABLE mdm_inventory.collection_output_chunks (
 tenant_id uuid NOT NULL,
 attempt uuid NOT NULL,
 chunk_index integer NOT NULL CHECK(chunk_index BETWEEN 0 AND 63),
 manifest jsonb NOT NULL CHECK(octet_length(manifest::text)<=1024),
 bytes bytea NOT NULL CHECK(octet_length(bytes) BETWEEN 1 AND 262144),
 PRIMARY KEY(tenant_id,attempt,chunk_index)
);
CREATE TABLE mdm_inventory.collection_policy_recovery (
 expected_epoch bigint NOT NULL CHECK(expected_epoch>0),
 tenant_id uuid NOT NULL,
 policy uuid NOT NULL,
 input_revision bigint NOT NULL DEFAULT 1,
 input_consumed bigint NOT NULL DEFAULT 0,
 input_window bigint NOT NULL DEFAULT 0,
 runs_done boolean NOT NULL DEFAULT false,
 recovery_after uuid,
 CHECK(input_revision>=input_window AND input_window>=input_consumed AND input_consumed>=0),
 PRIMARY KEY(tenant_id,policy)
);
CREATE TABLE mdm_inventory.collection_native_checkins (
    tenant_id uuid NOT NULL
  , device uuid NOT NULL
  , active_event uuid
  , active_at bigint
  , active_epoch bigint CHECK(active_epoch>0)
  , policy_after uuid
  , pending_event uuid
  , pending_at bigint
  , pending_epoch bigint CHECK(pending_epoch>0)
  , CHECK ((active_event IS NULL) = (active_epoch IS NULL))
  , CHECK ((active_event IS NULL) = (active_at IS NULL))
  , CHECK ((pending_event IS NULL) = (pending_epoch IS NULL))
  , CHECK ((pending_event IS NULL) = (pending_at IS NULL))
  , CHECK (active_event IS NOT NULL
        OR policy_after IS NULL)
  , CHECK (active_at IS NULL
        OR active_at >= 0)
  , CHECK (pending_at IS NULL
        OR pending_at >= 0)
  , PRIMARY KEY (tenant_id, device)
);
ALTER TABLE mdm_inventory.collection_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_inventory.collection_tasks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_inventory.collection_tasks
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_inventory.collection_admission ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_inventory.collection_admission FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_inventory.collection_admission
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_inventory.collection_output_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_inventory.collection_output_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_inventory.collection_output_chunks
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_inventory.collection_policy_recovery ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_inventory.collection_policy_recovery FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_inventory.collection_policy_recovery
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE mdm_inventory.collection_native_checkins ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_inventory.collection_native_checkins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_inventory.collection_native_checkins
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE INDEX collection_task_history ON mdm_inventory.collection_tasks(tenant_id,policy_version,available_at,id);
CREATE INDEX collection_agent_offer
  ON mdm_inventory.collection_tasks (tenant_id
                                   , device
                                   , available_at
                                   , id)
  WHERE channel = 'agent'
    AND agent_state ->> 'execution' = 'not_started'
    AND agent_state ->> 'cancellation' = 'none';
CREATE INDEX collection_native_delivery
  ON mdm_inventory.collection_tasks (tenant_id
                                   , device
                                   , available_at
                                   , id)
  WHERE channel = 'mdm'
    AND native_delivery IN ('queued', 'prepared');
CREATE INDEX collection_tasks_device_directory ON mdm_inventory.collection_tasks(tenant_id,device,id);
COMMIT;

CREATE POLICY work_discovery ON mdm_inventory.collection_tasks FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_inventory.collection_policy_recovery FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_inventory.collection_native_checkins FOR SELECT TO mdm_owner USING(true);
CREATE FUNCTION mdm_inventory.collection_work_scopes(after_tenant uuid) RETURNS TABLE(tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT tenant_id FROM (SELECT tenant_id FROM mdm_inventory.collection_tasks UNION SELECT tenant_id FROM mdm_inventory.collection_policy_recovery UNION SELECT tenant_id FROM mdm_inventory.collection_native_checkins UNION SELECT a.tenant_id FROM mdm_policy.assignments a JOIN mdm_policy.versions v ON (v.tenant_id,v.id)=(a.tenant_id,a.version) WHERE v.action_kind='native_collection') work
 WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32
$$;
CREATE FUNCTION mdm_inventory.collection_work_epoch(t uuid, entity text) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT expected_epoch FROM mdm_inventory.collection_tasks WHERE tenant_id=t AND 'run:'||id::text=entity
 UNION ALL SELECT expected_epoch FROM mdm_inventory.collection_policy_recovery WHERE tenant_id=t AND 'policy:'||policy::text=entity
 UNION ALL SELECT coalesce(active_epoch,pending_epoch) FROM mdm_inventory.collection_native_checkins WHERE tenant_id=t AND 'checkin:'||device::text=entity
 UNION ALL SELECT DISTINCT expected_epoch FROM mdm_policy.assignments WHERE tenant_id=t AND channel='mdm' AND 'scheduled:'||version::text||':'||(target->>'device')=entity
$$;
CREATE FUNCTION mdm_inventory.collection_work_relay_scopes(after_tenant uuid) RETURNS TABLE(tenant_id uuid,expected_epoch bigint,claimable boolean,quarantined boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT * FROM public.mdm_command_relay_tenants('mdm.collection.v1',after_tenant)
$$;
ALTER FUNCTION mdm_inventory.collection_work_scopes(uuid) OWNER TO mdm_owner;
ALTER FUNCTION mdm_inventory.collection_work_epoch(uuid,text) OWNER TO mdm_owner;
ALTER FUNCTION mdm_inventory.collection_work_relay_scopes(uuid) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_inventory.collection_work_scopes(uuid),mdm_inventory.collection_work_epoch(uuid,text),mdm_inventory.collection_work_relay_scopes(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_inventory.collection_work_scopes(uuid),mdm_inventory.collection_work_epoch(uuid,text),mdm_inventory.collection_work_relay_scopes(uuid) TO mdm_access;

CREATE FUNCTION mdm_inventory.windows_wake_inputs() RETURNS TABLE(tenant_id uuid,device uuid)
LANGUAGE sql STABLE AS $$
 SELECT t.tenant_id,t.device FROM mdm_inventory.collection_tasks t
 JOIN mdm_access.collection_runs r ON (r.tenant_id,r.id)=(t.tenant_id,t.collection_run)
 WHERE t.native_delivery IN ('prepared','sent') AND r.source='mdm.windows'
   AND r.sealed_at IS NULL AND t.deadline>floor(extract(epoch FROM statement_timestamp()))
$$;
REVOKE ALL ON FUNCTION mdm_inventory.windows_wake_inputs() FROM PUBLIC;
