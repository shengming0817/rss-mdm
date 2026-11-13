-- Fresh installation: Registration owns account access execution.
BEGIN;



CREATE TABLE rss_da.access_runs (
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
  , dispatch_fingerprint bytea NOT NULL CHECK (octet_length(dispatch_fingerprint) = 32)
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

CREATE TABLE rss_da.access_policy_recovery (
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
GRANT SELECT ON rss_da.access_runs TO da_access;
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
 AND a.device=p_device AND a.id=p_run AND a.state=p_previous
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(SELECT FROM rss_da.agent_delivery d WHERE d.tenant_id=a.tenant_id AND d.agent_device=a.device AND NOT d.enabled)
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION rss_da.save_retired_access_run(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_da.save_retired_access_run(uuid,uuid,jsonb,jsonb) TO da_access,da_command_runtime;
COMMIT;
