-- Fresh installation: Registration owns account access execution.
BEGIN;



CREATE TABLE rss_da.access_runs (
    expected_epoch bigint NOT NULL CHECK(expected_epoch>0),
    tenant_id uuid NOT NULL
  , id uuid NOT NULL
  , policy_version uuid NOT NULL
  , origin jsonb NOT NULL CHECK (origin IN ('"system"', '"policy"', '"human"', '"ai"'))
  , access_binding jsonb NOT NULL
  , binding_id uuid GENERATED ALWAYS AS (CAST(access_binding ->> 'id' AS uuid)) STORED
  , device uuid NOT NULL
  , occurrence text NOT NULL CHECK (octet_length(occurrence) BETWEEN 1 AND 256)
  , created_at bigint NOT NULL CHECK (created_at >= 0)
  , available_at bigint NOT NULL CHECK (available_at >= 0)
  , deadline bigint NOT NULL CHECK (deadline > available_at)
  , state jsonb NOT NULL CHECK (octet_length(CAST(state AS text)) <= 4096)
  , gateway_accepted boolean NOT NULL DEFAULT FALSE
  , da_target jsonb
  , da_journal jsonb NOT NULL DEFAULT '{}' CHECK (octet_length(da_journal::text)<=131072)
  , dispatch_fingerprint bytea CHECK (octet_length(dispatch_fingerprint) = 32)
  , CHECK ((da_target IS NULL) = (dispatch_fingerprint IS NOT NULL))
  , result jsonb CHECK (result IS NULL
                     OR octet_length(CAST(result AS text)) <= 1114112)
  , PRIMARY KEY (tenant_id, id)
  , FOREIGN KEY (tenant_id, binding_id) REFERENCES rss_da.bindings (tenant_id, id)
  , UNIQUE (tenant_id, policy_version, device, occurrence)
);

ALTER TABLE rss_da.access_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_da.access_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON rss_da.access_runs
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

-- Event receipts are immutable and scoped to the authenticated run. An offline
-- device can renew an unstarted permit without consuming its final result slot.
CREATE TABLE rss_da.account_events (
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    event uuid NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    permit_until bigint,
    receipt jsonb,
    PRIMARY KEY (tenant_id,run,event),
    FOREIGN KEY (tenant_id,run) REFERENCES rss_da.access_runs(tenant_id,id)
);
ALTER TABLE rss_da.account_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_da.account_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_da.account_events
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON rss_da.account_events TO da_access;

CREATE TABLE rss_da.access_policy_recovery (
    expected_epoch bigint NOT NULL CHECK(expected_epoch>0),
    tenant_id uuid NOT NULL,
    policy uuid NOT NULL,
    input_revision bigint NOT NULL DEFAULT 1,
    input_consumed bigint NOT NULL DEFAULT 0,
    input_window bigint NOT NULL DEFAULT 0,
    recovery_after uuid,
    runs_done boolean NOT NULL DEFAULT false,
    PRIMARY KEY(tenant_id,policy),
    CHECK(input_revision>=input_consumed AND input_consumed>=0)
);

ALTER TABLE rss_da.access_policy_recovery ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_da.access_policy_recovery FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON rss_da.access_policy_recovery
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE INDEX access_offer
  ON rss_da.access_runs (tenant_id
                       , device
                       , available_at
                       , id)
  WHERE state ->> 'execution' = 'not_started'
    AND state ->> 'cancellation' = 'none';

CREATE INDEX access_history ON rss_da.access_runs(tenant_id,policy_version,available_at,id);

ALTER TABLE rss_da.access_runs ADD FOREIGN KEY(tenant_id,policy_version) REFERENCES rss_da.policy_versions(tenant_id,id);
ALTER TABLE rss_da.access_policy_recovery ADD FOREIGN KEY(tenant_id,policy) REFERENCES rss_da.policies(tenant_id,id);
GRANT USAGE ON SCHEMA rss_da TO da_command_runtime,da_policy_runtime,da_access;
GRANT SELECT,INSERT ON rss_da.access_runs,rss_da.access_policy_recovery TO da_command_runtime,da_policy_runtime;
GRANT UPDATE(state,result) ON rss_da.access_runs TO da_command_runtime,da_policy_runtime;
GRANT UPDATE(gateway_accepted) ON rss_da.access_runs TO da_command_runtime;
GRANT SELECT,UPDATE(state,result,da_journal) ON rss_da.access_runs TO da_access;
GRANT SELECT,INSERT ON rss_da.access_runs TO da_identity_runtime;
CREATE POLICY targeted_update ON rss_da.access_runs AS RESTRICTIVE FOR UPDATE TO da_access
 USING(da_target IS NOT NULL) WITH CHECK(da_target IS NOT NULL);
CREATE POLICY access_management_insert ON rss_da.access_runs AS RESTRICTIVE FOR INSERT TO da_identity_runtime
 WITH CHECK(da_target IS NOT NULL);
CREATE POLICY access_agent_path ON rss_da.access_runs AS RESTRICTIVE TO da_command_runtime,da_policy_runtime
 USING(da_target IS NULL) WITH CHECK(da_target IS NULL);
CREATE UNIQUE INDEX access_da_revision ON rss_da.access_runs (tenant_id,binding_id,((access_binding->>'revision')::bigint)) WHERE da_target IS NOT NULL;
GRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON rss_da.access_policy_recovery TO da_command_runtime;
GRANT UPDATE(input_revision) ON rss_da.access_policy_recovery TO da_policy_runtime;
COMMIT;
-- Registration retirement participates on the initiating audit connection.
BEGIN;
CREATE FUNCTION rss_da.save_retired_access_run(p_device uuid,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE rss_da.access_runs a SET state=p_state
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.da_target IS NULL AND a.device=p_device AND a.id=p_run AND a.state=p_previous
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(SELECT FROM rss_da.agent_delivery d WHERE d.tenant_id=a.tenant_id AND d.agent_device=a.device AND NOT d.enabled)
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION rss_da.save_retired_access_run(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.save_retired_access_run(uuid,uuid,jsonb,jsonb) TO da_access,da_command_runtime;
CREATE INDEX access_runs_device_directory ON rss_da.access_runs(tenant_id,device,id) WHERE da_target IS NULL;
COMMIT;

CREATE POLICY work_discovery ON rss_da.access_runs FOR SELECT TO da_owner USING(true);
CREATE POLICY work_discovery ON rss_da.access_policy_recovery FOR SELECT TO da_owner USING(true);
CREATE FUNCTION rss_da.access_runs_work_scopes(after_tenant uuid) RETURNS TABLE(tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT tenant_id FROM (SELECT tenant_id FROM rss_da.access_runs WHERE da_target IS NULL UNION SELECT tenant_id FROM rss_da.access_policy_recovery) work
 WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32
$$;
CREATE FUNCTION rss_da.access_runs_work_epoch(t uuid, entity text) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT expected_epoch FROM rss_da.access_runs WHERE tenant_id=t AND da_target IS NULL AND 'run:'||id::text=entity
 UNION ALL SELECT expected_epoch FROM rss_da.access_policy_recovery WHERE tenant_id=t AND 'policy:'||policy::text=entity
$$;
CREATE FUNCTION rss_da.access_runs_work_relay_scopes(after_tenant uuid) RETURNS TABLE(tenant_id uuid,expected_epoch bigint,claimable boolean,quarantined boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT * FROM public.mdm_command_relay_tenants('mdm.registration.access.v1',after_tenant)
$$;
ALTER FUNCTION rss_da.access_runs_work_scopes(uuid) OWNER TO da_owner;
ALTER FUNCTION rss_da.access_runs_work_epoch(uuid,text) OWNER TO da_owner;
ALTER FUNCTION rss_da.access_runs_work_relay_scopes(uuid) OWNER TO da_owner;
REVOKE ALL ON FUNCTION rss_da.access_runs_work_scopes(uuid),rss_da.access_runs_work_epoch(uuid,text),rss_da.access_runs_work_relay_scopes(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.access_runs_work_scopes(uuid),rss_da.access_runs_work_epoch(uuid,text),rss_da.access_runs_work_relay_scopes(uuid) TO da_access;
