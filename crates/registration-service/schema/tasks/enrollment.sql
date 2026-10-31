-- Fresh installation: Script owns its complete execution state.
BEGIN;

CREATE SCHEMA mdm_registration_tasks;

CREATE TABLE mdm_registration_tasks.runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    policy_version uuid NOT NULL,
    origin jsonb NOT NULL CHECK(origin IN ('"system"','"policy"','"human"','"ai"')),
    source_objects jsonb NOT NULL,
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
    dispatch_failure jsonb CHECK(dispatch_failure IS NULL OR octet_length(dispatch_failure::text)<=8192),
    result jsonb CHECK(result IS NULL OR octet_length(result::text)<=1114112),
    invocation jsonb CHECK(invocation IS NULL OR (jsonb_typeof(invocation)='object' AND octet_length(invocation::text)<=131072)),
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,policy_version,device,occurrence)
);

ALTER TABLE mdm_registration_tasks.runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_registration_tasks.runs FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_registration_tasks.runs
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_registration_tasks.receipts (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
    response jsonb NOT NULL CHECK(octet_length(response::text)<=6291456),
    PRIMARY KEY(tenant_id,actor,id)
);

ALTER TABLE mdm_registration_tasks.receipts ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_registration_tasks.receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_registration_tasks.receipts
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_registration_tasks.agent_admission (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    policy_after uuid,
    PRIMARY KEY(tenant_id,registration)
);

ALTER TABLE mdm_registration_tasks.agent_admission ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_registration_tasks.agent_admission FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_registration_tasks.agent_admission
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_registration_tasks.policy_recovery (
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

ALTER TABLE mdm_registration_tasks.policy_recovery ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_registration_tasks.policy_recovery FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_registration_tasks.policy_recovery
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE INDEX enrollment_offer ON mdm_registration_tasks.runs(tenant_id,registration,available_at,id)
 WHERE state->>'execution'='not_started' AND state->>'cancellation'='none';

CREATE INDEX enrollment_history ON mdm_registration_tasks.runs(tenant_id,policy_version,available_at,id);

COMMIT;