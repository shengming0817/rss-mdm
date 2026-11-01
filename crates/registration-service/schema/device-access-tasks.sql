-- Fresh installation: Registration owns account access execution.
BEGIN;

CREATE SCHEMA mdm_access_tasks;

CREATE TABLE mdm_access_tasks.runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    policy_version uuid NOT NULL,
    origin jsonb NOT NULL CHECK(origin IN ('"system"','"policy"','"human"','"ai"')),
    access_binding jsonb NOT NULL,
    device text NOT NULL,
    registration uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    occurrence text NOT NULL CHECK(octet_length(occurrence) BETWEEN 1 AND 256),
    created_at bigint NOT NULL CHECK(created_at>=0),
    available_at bigint NOT NULL CHECK(available_at>=0),
    deadline bigint NOT NULL CHECK(deadline>available_at),
    state jsonb NOT NULL CHECK(octet_length(state::text)<=4096),
    gateway_accepted boolean NOT NULL DEFAULT false,
    dispatch_fingerprint bytea NOT NULL CHECK(octet_length(dispatch_fingerprint)=32),
    result jsonb CHECK(result IS NULL OR octet_length(result::text)<=1114112),
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,policy_version,device,occurrence)
);

ALTER TABLE mdm_access_tasks.runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access_tasks.runs FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_access_tasks.runs
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_access_tasks.policy_recovery (
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

ALTER TABLE mdm_access_tasks.policy_recovery ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_access_tasks.policy_recovery FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_access_tasks.policy_recovery
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE INDEX access_offer ON mdm_access_tasks.runs(tenant_id,registration,available_at,id)
 WHERE state->>'execution'='not_started' AND state->>'cancellation'='none';

CREATE INDEX access_history ON mdm_access_tasks.runs(tenant_id,policy_version,available_at,id);

ALTER TABLE mdm_access_tasks.runs ADD FOREIGN KEY(tenant_id,policy_version) REFERENCES mdm_policy.versions(tenant_id,id);
ALTER TABLE mdm_access_tasks.runs ADD FOREIGN KEY(tenant_id,device) REFERENCES mdm_access.devices(tenant_id,id);
ALTER TABLE mdm_access_tasks.runs ADD FOREIGN KEY(tenant_id,registration) REFERENCES mdm_access.registrations(tenant_id,id);
ALTER TABLE mdm_access_tasks.policy_recovery ADD FOREIGN KEY(tenant_id,policy) REFERENCES mdm_policy.policies(tenant_id,id);
GRANT USAGE ON SCHEMA mdm_access_tasks TO mdm_command_runtime,mdm_policy_runtime,mdm_access;
GRANT SELECT,INSERT ON mdm_access_tasks.runs,mdm_access_tasks.policy_recovery TO mdm_command_runtime,mdm_policy_runtime;
GRANT UPDATE(state,result) ON mdm_access_tasks.runs TO mdm_command_runtime,mdm_policy_runtime;
GRANT UPDATE(gateway_accepted) ON mdm_access_tasks.runs TO mdm_command_runtime;
GRANT SELECT ON mdm_access_tasks.runs TO mdm_access;
GRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON mdm_access_tasks.policy_recovery TO mdm_command_runtime;
GRANT UPDATE(input_revision) ON mdm_access_tasks.policy_recovery TO mdm_policy_runtime;
COMMIT;
-- Registration retirement participates on the initiating audit connection.
BEGIN;
SET LOCAL check_function_bodies = false;
CREATE FUNCTION mdm_access_tasks.save_retired_run(p_registration uuid,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE mdm_access_tasks.runs a SET state=p_state
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.registration=p_registration AND a.id=p_run AND a.state=p_previous
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.registration) AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM mdm_access.devices d WHERE (d.tenant_id,d.id)=(r.tenant_id,r.device) AND d.retirement IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id)))))
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;
REVOKE ALL ON FUNCTION mdm_access_tasks.save_retired_run(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mdm_access_tasks.save_retired_run(uuid,uuid,jsonb,jsonb) TO mdm_access,mdm_command_runtime;
COMMIT;
