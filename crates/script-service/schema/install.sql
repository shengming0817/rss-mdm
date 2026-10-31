-- Fresh installation: Script owns its complete execution state.
BEGIN;
CREATE SCHEMA mdm_script;

CREATE TABLE mdm_script.runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    policy_version uuid NOT NULL,
    resource_id text NOT NULL CHECK(octet_length(resource_id) BETWEEN 1 AND 256),
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
ALTER TABLE mdm_script.runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_script.runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_script.runs
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_script.receipts (
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
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    policy_after uuid,
    offer_after_at bigint,
    offer_after_id uuid,
    CHECK((offer_after_at IS NULL)=(offer_after_id IS NULL)),
    PRIMARY KEY(tenant_id,registration)
);
ALTER TABLE mdm_script.agent_admission ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_script.agent_admission FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_script.agent_admission
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_script.policy_recovery (
    tenant_id uuid NOT NULL,
    policy uuid NOT NULL,
    input_revision bigint NOT NULL DEFAULT 1,
    input_consumed bigint NOT NULL DEFAULT 0,
    target_after text,
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
CREATE INDEX script_offer ON mdm_script.runs(tenant_id,registration,available_at,id)
 WHERE state->>'execution'='not_started' AND state->>'cancellation'='none';
CREATE INDEX script_history ON mdm_script.runs(tenant_id,policy_version,available_at,id);
COMMIT;
