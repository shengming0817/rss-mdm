-- Fresh installation: execution owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_commands;

CREATE FUNCTION mdm_commands.installation_status(p_operation uuid) RETURNS text
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT d.status FROM mdm_commands.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND o.id=p_operation AND o.approval->>'kind'='agent_install';
$$;

REVOKE ALL ON FUNCTION mdm_commands.installation_status(uuid) FROM PUBLIC;

CREATE TABLE mdm_commands.action_attempts (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    run uuid NOT NULL,
    registration uuid NOT NULL,
    claimed_at bigint NOT NULL,
    offer jsonb NOT NULL,
    permit jsonb,
    CONSTRAINT action_attempts_claimed_at_check CHECK ((claimed_at >= 0)),
    CONSTRAINT action_attempts_offer_check CHECK ((octet_length((offer)::text) <= 6291456)),
    CONSTRAINT action_attempts_permit_check CHECK (((permit IS NULL) OR (octet_length((permit)::text) <= 6291456)))
);

ALTER TABLE ONLY mdm_commands.action_attempts FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.action_polls (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    cancellation_after uuid,
    policy_after uuid
);

ALTER TABLE ONLY mdm_commands.action_polls FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.action_receipts (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    audit_details jsonb,
    CONSTRAINT action_receipts_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT action_receipts_response_check CHECK ((octet_length((response)::text) <= 6291456))
);

ALTER TABLE ONLY mdm_commands.action_receipts FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.action_runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    source_kind text DEFAULT 'policy'::text NOT NULL,
    policy_version uuid,
    remote_operation uuid,
    device text NOT NULL,
    registration uuid NOT NULL,
    generation bigint NOT NULL,
    occurrence text NOT NULL,
    created_at bigint NOT NULL,
    available_at bigint NOT NULL,
    deadline bigint NOT NULL,
    state jsonb NOT NULL,
    gateway_accepted boolean DEFAULT false NOT NULL,
    dispatch_fingerprint bytea NOT NULL,
    dispatch_failure jsonb CHECK (dispatch_failure IS NULL OR (jsonb_typeof(dispatch_failure)='object' AND octet_length(dispatch_failure::text)<=8192)),
    result jsonb,
    CONSTRAINT action_runs_available_at_check CHECK ((available_at >= 0)),
    CONSTRAINT action_runs_check CHECK ((((source_kind = 'policy'::text) AND (policy_version IS NOT NULL) AND (remote_operation IS NULL)) OR ((source_kind = 'remote_operation'::text) AND (policy_version IS NULL) AND (remote_operation IS NOT NULL)))),
    CONSTRAINT action_runs_check1 CHECK ((deadline > available_at)),
    CONSTRAINT action_runs_created_at_check CHECK ((created_at >= 0)),
    CONSTRAINT action_runs_dispatch_fingerprint_check CHECK ((octet_length(dispatch_fingerprint) = 32)),
    CONSTRAINT action_runs_generation_check CHECK ((generation > 0)),
    CONSTRAINT action_runs_occurrence_check CHECK (((octet_length(occurrence) >= 1) AND (octet_length(occurrence) <= 256))),
    CONSTRAINT action_runs_result_check CHECK ((octet_length((result)::text) <= 1114112)),
    CONSTRAINT action_runs_state_check CHECK ((octet_length((state)::text) <= 4096))
);

ALTER TABLE ONLY mdm_commands.action_runs FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.apple_profiles (
    tenant_id uuid NOT NULL, device text NOT NULL, user_key text NOT NULL,
    identifier text NOT NULL, profile uuid NOT NULL, operation uuid NOT NULL,
    registration uuid NOT NULL, version text NOT NULL,
    CONSTRAINT profiles_version_check CHECK (octet_length(version) BETWEEN 1 AND 128)
);

ALTER TABLE ONLY mdm_commands.apple_profiles FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.attempts (
    tenant_id uuid NOT NULL, id uuid NOT NULL, operation uuid NOT NULL,
    ordinal bigint NOT NULL, credential uuid NOT NULL, session bigint NOT NULL,
    message bigint NOT NULL, phase text NOT NULL, request bytea NOT NULL, platform jsonb,
    CONSTRAINT attempts_ordinal_check CHECK (ordinal > 0),
    CONSTRAINT attempts_phase_check CHECK (phase IN ('prepare','execute','observe'))
);

CREATE TABLE mdm_commands.attempt_items (
    tenant_id uuid NOT NULL, attempt uuid NOT NULL, command bigint NOT NULL,
    item_ordinal integer NOT NULL, parent_command bigint, kind text NOT NULL, uri text,
    status integer, value bytea, received_at bigint, receipt_accepted boolean,
    result_received_at bigint, result_accepted boolean,
    PRIMARY KEY(tenant_id,attempt,command,item_ordinal),
    CHECK (command BETWEEN 1 AND 4294967295), CHECK (item_ordinal >= 0),
    CHECK (kind IN ('get','add','replace','delete','exec','atomic','sequence')),
    CHECK ((kind IN ('atomic','sequence')) = (uri IS NULL)),
    CHECK (status IS NULL OR status BETWEEN 100 AND 599),
    CHECK (value IS NULL OR octet_length(value) BETWEEN 68 AND 16777284)
);

ALTER TABLE ONLY mdm_commands.attempt_items FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_commands.attempts FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.capabilities (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    generation bigint NOT NULL,
    os_version text NOT NULL,
    edition integer NOT NULL,
    session bigint NOT NULL,
    observed_at bigint NOT NULL
);

ALTER TABLE ONLY mdm_commands.capabilities FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.capability_queries (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    generation bigint NOT NULL,
    session bigint NOT NULL,
    request bytea NOT NULL,
    version_command bigint NOT NULL,
    edition_command bigint NOT NULL,
    os_version text,
    edition text,
    version_status integer,
    edition_status integer,
    session_id text GENERATED ALWAYS AS ((session)::text) STORED NOT NULL
);

ALTER TABLE ONLY mdm_commands.capability_queries FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.devices (
    tenant_id uuid NOT NULL,
    device text NOT NULL,
    command_device uuid NOT NULL,
    generation bigint NOT NULL,
    epoch bigint NOT NULL,
    registration uuid NOT NULL,
    registration_generation bigint NOT NULL,
    recovery_after text,
    CONSTRAINT devices_epoch_check CHECK ((epoch > 0)),
    CONSTRAINT devices_generation_check CHECK ((generation > 0)),
    CONSTRAINT devices_registration_generation_check CHECK ((registration_generation > 0))
);

ALTER TABLE ONLY mdm_commands.devices FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    device text NOT NULL,
    request bytea NOT NULL,
    input_context jsonb NOT NULL CHECK (jsonb_typeof(input_context)='object' AND octet_length(input_context::text)<=4096),
    fingerprint bytea NOT NULL,
    registration uuid NOT NULL,
    registration_generation bigint NOT NULL,
    generation bigint NOT NULL,
    epoch bigint NOT NULL,
    approval jsonb NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    dispatch_fingerprint bytea NOT NULL,
    dispatch_failure jsonb CHECK (dispatch_failure IS NULL OR (jsonb_typeof(dispatch_failure)='object' AND octet_length(dispatch_failure::text)<=8192)),
    gateway_accepted boolean DEFAULT false NOT NULL,
    source_kind text DEFAULT 'direct'::text NOT NULL,
    policy_version uuid,
    remote_operation uuid,
    CONSTRAINT operation_authority_source CHECK (COALESCE(
CASE source_kind
    WHEN 'direct'::text THEN ((approval ->> 'kind'::text) = 'user'::text)
    WHEN 'policy'::text THEN (((approval ->> 'kind'::text) IN ('policy'::text,'agent_install'::text)) AND ((approval ->> 'tenant'::text) = (tenant_id)::text) AND ((approval ->> 'device'::text) = device) AND ((approval ->> 'version'::text) = (policy_version)::text))
    WHEN 'remote_operation'::text THEN (((approval ->> 'kind'::text) = 'remote_operation'::text) AND ((approval ->> 'tenant'::text) = (tenant_id)::text) AND ((approval ->> 'device'::text) = device) AND ((approval ->> 'operation'::text) = (remote_operation)::text))
    ELSE NULL::boolean
END, false)),
    CONSTRAINT operation_source CHECK ((((source_kind = 'direct'::text) AND (policy_version IS NULL) AND (remote_operation IS NULL)) OR ((source_kind = 'policy'::text) AND (policy_version IS NOT NULL) AND (remote_operation IS NULL)) OR ((source_kind = 'remote_operation'::text) AND (policy_version IS NULL) AND (remote_operation IS NOT NULL)))),
    CONSTRAINT operations_approval_check CHECK ((octet_length((approval)::text) <= 1048576)),
    CONSTRAINT operations_dispatch_fingerprint_check CHECK ((octet_length(dispatch_fingerprint) = 32)),
    CONSTRAINT operations_epoch_check CHECK ((epoch > 0)),
    CONSTRAINT operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT operations_generation_check CHECK ((generation > 0)),
    CONSTRAINT operations_registration_generation_check CHECK ((registration_generation > 0)),
    CONSTRAINT operations_request_check CHECK ((octet_length(request) BETWEEN 68 AND 33554500)),
    CONSTRAINT operations_revision_check CHECK ((revision > 0)),
    CONSTRAINT operations_source_kind_check CHECK ((source_kind = ANY (ARRAY['direct'::text, 'policy'::text, 'remote_operation'::text])))
);

ALTER TABLE ONLY mdm_commands.operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.policy_recovery (
    target_after text,
    tenant_id uuid NOT NULL,
    policy uuid NOT NULL,
    recovery_after uuid
);

ALTER TABLE ONLY mdm_commands.policy_recovery FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.requests (
    tenant_id uuid NOT NULL,
    actor text NOT NULL CHECK(length(actor)>0),
    id uuid NOT NULL,
    operation uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    CONSTRAINT requests_fingerprint_check CHECK ((octet_length(fingerprint) = 32))
);

ALTER TABLE ONLY mdm_commands.requests FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_flow.native_protection (
    tenant_id uuid PRIMARY KEY,
    key_id text NOT NULL CHECK (key_id ~ '^[0-9a-f]{64}$')
);

ALTER TABLE mdm_flow.native_protection ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_flow.native_protection FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_flow.native_protection USING (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE mdm_planning.configuration_claims (
    tenant_id uuid NOT NULL,
    policy uuid NOT NULL,
    device text NOT NULL,
    version uuid NOT NULL,
    operation uuid,
    user_key text NOT NULL, platform text NOT NULL, object_kind text NOT NULL, object_key text NOT NULL
);

ALTER TABLE ONLY mdm_planning.configuration_claims FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.configuration_devices (
    tenant_id uuid NOT NULL,
    device text NOT NULL,
    input_revision bigint DEFAULT 1 NOT NULL,
    observed_revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT configuration_devices_input_revision_check CHECK ((input_revision > 0)),
    CONSTRAINT configuration_devices_observed_revision_check CHECK ((observed_revision >= 0))
);

ALTER TABLE ONLY mdm_planning.configuration_devices FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.configuration_objects (
    tenant_id uuid NOT NULL, device text NOT NULL, user_key text NOT NULL,
    platform text NOT NULL CHECK(platform IN ('windows','macos')),
    object_kind text NOT NULL CHECK(object_kind IN ('csp','profile','payload','declaration')),
    object_key text NOT NULL CHECK(octet_length(object_key) BETWEEN 1 AND 2048),
    operation uuid, digest bytea CHECK(digest IS NULL OR octet_length(digest)=32),
    diagnosis text CHECK(diagnosis IN ('waiting_scope','waiting_registration','waiting_capability','not_applicable','configuration_conflict','native_group_conflict','removal_blocked_by_shared_unit','removing','unassigned')),
    PRIMARY KEY(tenant_id,device,user_key,platform,object_kind,object_key)
);

ALTER TABLE ONLY mdm_planning.configuration_objects FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.remote_operation_targets (
    tenant_id uuid NOT NULL,
    operation uuid NOT NULL,
    device text NOT NULL,
    status text NOT NULL,
    delivery_id uuid,
    diagnosis text,
    CONSTRAINT remote_operation_targets_check CHECK (((status = 'accepted'::text) = (delivery_id IS NOT NULL))),
    CONSTRAINT remote_operation_targets_status_check CHECK ((status = ANY (ARRAY['accepted'::text, 'blocked'::text])))
);

ALTER TABLE ONLY mdm_planning.remote_operation_targets FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.remote_operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    resource text NOT NULL,
    resource_version text NOT NULL,
    frozen jsonb NOT NULL,
    snapshot jsonb NOT NULL,
    created_at bigint NOT NULL,
    deadline bigint NOT NULL,
    author jsonb NOT NULL,
    cancelled boolean DEFAULT false NOT NULL,
    staged boolean DEFAULT false NOT NULL,
    cursor text,
    run_after uuid,
    CONSTRAINT remote_operations_check CHECK ((deadline > created_at)),
    CONSTRAINT remote_operations_frozen_check CHECK ((octet_length((frozen)::text) <= 25165824)),
    CONSTRAINT remote_operations_snapshot_check CHECK ((octet_length((snapshot)::text) <= 4194304))
);

ALTER TABLE ONLY mdm_planning.remote_operations FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_commands.action_attempts
    ADD CONSTRAINT action_attempts_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_polls
    ADD CONSTRAINT action_polls_pkey PRIMARY KEY (tenant_id, registration);

ALTER TABLE ONLY mdm_commands.action_receipts
    ADD CONSTRAINT action_receipts_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_tenant_id_policy_version_occurrence_device_key UNIQUE (tenant_id, policy_version, occurrence, device);

ALTER TABLE ONLY mdm_commands.action_runs
    ADD CONSTRAINT action_runs_tenant_id_remote_operation_device_key UNIQUE (tenant_id, remote_operation, device);

ALTER TABLE ONLY mdm_commands.attempts
    ADD CONSTRAINT attempts_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_commands.attempts
    ADD CONSTRAINT attempts_tenant_id_operation_ordinal_key UNIQUE (tenant_id, operation, ordinal);

ALTER TABLE ONLY mdm_commands.capabilities
    ADD CONSTRAINT capabilities_pkey PRIMARY KEY (tenant_id, registration);

ALTER TABLE ONLY mdm_commands.capability_queries
    ADD CONSTRAINT capability_queries_pkey PRIMARY KEY (tenant_id, registration, session);

ALTER TABLE ONLY mdm_commands.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (tenant_id, device);

ALTER TABLE ONLY mdm_commands.devices
    ADD CONSTRAINT devices_tenant_id_command_device_key UNIQUE (tenant_id, command_device);

ALTER TABLE ONLY mdm_commands.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_commands.policy_recovery
    ADD CONSTRAINT policy_recovery_pkey PRIMARY KEY (tenant_id, policy);

ALTER TABLE ONLY mdm_commands.apple_profiles
    ADD CONSTRAINT profiles_pkey PRIMARY KEY (tenant_id, device, user_key, identifier);

ALTER TABLE ONLY mdm_commands.apple_profiles
    ADD CONSTRAINT profiles_tenant_id_identifier_key UNIQUE (tenant_id, identifier);

ALTER TABLE ONLY mdm_commands.requests
    ADD CONSTRAINT requests_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE ONLY mdm_planning.configuration_claims
    ADD CONSTRAINT configuration_claims_pkey PRIMARY KEY (tenant_id, policy, device, user_key, platform, object_kind, object_key);

ALTER TABLE ONLY mdm_planning.configuration_devices
    ADD CONSTRAINT configuration_devices_pkey PRIMARY KEY (tenant_id, device);

ALTER TABLE ONLY mdm_planning.remote_operation_targets
    ADD CONSTRAINT remote_operation_targets_pkey PRIMARY KEY (tenant_id, operation, device);

ALTER TABLE ONLY mdm_planning.remote_operations
    ADD CONSTRAINT remote_operations_pkey PRIMARY KEY (tenant_id, id);

CREATE INDEX action_due ON mdm_commands.action_runs USING btree (tenant_id, registration, available_at, id);

CREATE INDEX action_runs_software_stage_latest ON mdm_commands.action_runs USING btree (tenant_id, policy_version, device, created_at DESC, id DESC);

CREATE INDEX native_session_receipts ON mdm_commands.attempt_items USING btree (tenant_id, attempt, command) WHERE receipt_accepted;

CREATE UNIQUE INDEX remote_native_once ON mdm_commands.operations USING btree (tenant_id, remote_operation, device) WHERE (remote_operation IS NOT NULL);

ALTER TABLE mdm_commands.action_attempts ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.action_polls ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.action_receipts ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.action_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.apple_profiles ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.attempts ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.capabilities ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.capability_queries ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.devices ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.policy_recovery ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_commands.action_attempts USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.action_polls USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.action_receipts USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.action_runs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.apple_profiles USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.attempts USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.capabilities USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.capability_queries USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.devices USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.policy_recovery USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_commands.requests USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_planning.configuration_claims ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.configuration_devices ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.configuration_objects ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.remote_operation_targets ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.remote_operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_planning.configuration_claims USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.configuration_devices USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.configuration_objects USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.remote_operation_targets USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.remote_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE TABLE mdm_commands.output_chunks (
 tenant_id uuid NOT NULL,attempt uuid NOT NULL,chunk_index integer NOT NULL CHECK(chunk_index>=0 AND chunk_index<64),
 manifest jsonb NOT NULL CHECK(octet_length(manifest::text)<=1024),bytes bytea NOT NULL CHECK(octet_length(bytes) BETWEEN 1 AND 262144),
 PRIMARY KEY(tenant_id,attempt,chunk_index),FOREIGN KEY(tenant_id,attempt) REFERENCES mdm_commands.action_attempts(tenant_id,id)
);

ALTER TABLE mdm_commands.output_chunks ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_commands.output_chunks FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_commands.output_chunks USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

REVOKE ALL ON mdm_commands.output_chunks FROM PUBLIC;

ALTER TABLE mdm_commands.attempt_items ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_commands.attempt_items USING (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);

COMMIT;
