-- Fresh installation: Script owns its complete execution state.
BEGIN;
CREATE SCHEMA mdm_script;

CREATE TABLE mdm_script.runs (
    expected_epoch bigint NOT NULL CHECK(expected_epoch>0),
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    policy_version uuid NOT NULL,
    resource_id text NOT NULL CHECK(octet_length(resource_id) BETWEEN 1 AND 256),
    origin jsonb NOT NULL CHECK(origin IN ('"system"','"policy"','"human"','"ai"')),
    source_objects jsonb NOT NULL,
    device uuid NOT NULL,
    occurrence text NOT NULL CHECK(octet_length(occurrence) BETWEEN 1 AND 256),
    created_at bigint NOT NULL CHECK(created_at>=0),
    available_at bigint NOT NULL CHECK(available_at>=0),
    deadline bigint NOT NULL CHECK(deadline>available_at),
    state jsonb NOT NULL CHECK(octet_length(state::text)<=4096),
    gateway_accepted boolean NOT NULL DEFAULT false,
    dispatch_fingerprint bytea NOT NULL CHECK(octet_length(dispatch_fingerprint)=32),
    dispatch_failure jsonb CHECK(dispatch_failure IS NULL OR octet_length(dispatch_failure::text)<=8192),
    result jsonb CHECK(result IS NULL OR octet_length(result::text)<=1114112),
    invocation jsonb CHECK(invocation IS NULL OR (jsonb_typeof(invocation)='object' AND octet_length(invocation::text)<=131072)),
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,policy_version,device,occurrence)
);
ALTER TABLE mdm_script.runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_script.runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_script.runs
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_script.receipts (
    device uuid NOT NULL,
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
    response jsonb NOT NULL CHECK(octet_length(response::text)<=6291456),
    PRIMARY KEY(tenant_id,actor,id)
);
ALTER TABLE mdm_script.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_script.receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_script.receipts
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_script.output_chunks (
    tenant_id uuid NOT NULL,
    attempt uuid NOT NULL,
    chunk_index integer NOT NULL CHECK(chunk_index BETWEEN 0 AND 63),
    manifest jsonb NOT NULL CHECK(octet_length(manifest::text)<=1024),
    bytes bytea NOT NULL CHECK(octet_length(bytes) BETWEEN 1 AND 262144),
    PRIMARY KEY(tenant_id,attempt,chunk_index)
);
ALTER TABLE mdm_script.output_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_script.output_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_script.output_chunks
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_script.agent_admission (
    expected_epoch bigint NOT NULL CHECK(expected_epoch>0),
    tenant_id uuid NOT NULL,
    device uuid NOT NULL,
    policy_after uuid,
    PRIMARY KEY(tenant_id,device)
);
ALTER TABLE mdm_script.agent_admission ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_script.agent_admission FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_script.agent_admission
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_script.policy_recovery (
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
ALTER TABLE mdm_script.policy_recovery ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_script.policy_recovery FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_script.policy_recovery
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE INDEX script_unknown_resource ON mdm_script.runs(tenant_id,device,resource_id)
 WHERE state->>'execution'='unknown';
CREATE INDEX script_offer ON mdm_script.runs(tenant_id,device,available_at,id)
 WHERE state->>'execution'='not_started' AND state->>'cancellation'='none';
CREATE INDEX script_device_history ON mdm_script.runs(tenant_id,device,id);
CREATE INDEX script_history ON mdm_script.runs(tenant_id,policy_version,available_at,id);
COMMIT;

-- Discover only original owner work coordinates through the shared read role.
CREATE POLICY work_discovery ON mdm_script.runs FOR SELECT TO mdm_owner USING(true);
CREATE POLICY work_discovery ON mdm_script.policy_recovery FOR SELECT TO mdm_owner USING(true);
CREATE FUNCTION mdm_script.work_scopes(after_tenant uuid) RETURNS TABLE(tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT tenant_id FROM (SELECT tenant_id FROM mdm_script.runs UNION SELECT tenant_id FROM mdm_script.policy_recovery) work
 WHERE after_tenant IS NULL OR tenant_id>after_tenant ORDER BY tenant_id LIMIT 32
$$;
CREATE FUNCTION mdm_script.work_epoch(t uuid, entity text) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT expected_epoch FROM mdm_script.runs WHERE tenant_id=t AND 'run:'||id::text=entity
 UNION ALL SELECT expected_epoch FROM mdm_script.policy_recovery WHERE tenant_id=t AND 'policy:'||policy::text=entity
$$;
CREATE FUNCTION mdm_script.relay_scopes(after_tenant uuid) RETURNS TABLE(tenant_id uuid,expected_epoch bigint,claimable boolean,quarantined boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT * FROM public.mdm_command_relay_tenants('mdm.script.v1',after_tenant)
$$;
ALTER FUNCTION mdm_script.work_scopes(uuid) OWNER TO mdm_owner;
ALTER FUNCTION mdm_script.work_epoch(uuid,text) OWNER TO mdm_owner;
ALTER FUNCTION mdm_script.relay_scopes(uuid) OWNER TO mdm_owner;
REVOKE ALL ON FUNCTION mdm_script.work_scopes(uuid),mdm_script.work_epoch(uuid,text),mdm_script.relay_scopes(uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_script TO mdm_access;
GRANT EXECUTE ON FUNCTION mdm_script.work_scopes(uuid),mdm_script.work_epoch(uuid,text),mdm_script.relay_scopes(uuid) TO mdm_access;
