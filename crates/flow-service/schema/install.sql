-- Fresh installation: flow-service owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_automation;

CREATE SCHEMA mdm_commands;

CREATE SCHEMA mdm_flow;

CREATE SCHEMA mdm_planning;

CREATE SCHEMA mdm_publication;

CREATE SCHEMA mdm_resource_catalog;

CREATE FUNCTION mdm_planning.policy_lock(p_policy uuid) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT FROM mdm_policy.policies WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND id=p_policy FOR SHARE;
$$;

CREATE FUNCTION mdm_planning.remote_target_page(p_operation uuid, p_after text, p_limit integer) RETURNS TABLE(device text)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 WITH operation AS (SELECT snapshot FROM mdm_planning.remote_operations WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND id=p_operation), targets AS (
 SELECT jsonb_array_elements_text(snapshot->'devices') AS device FROM operation WHERE snapshot->>'kind'='devices'
 UNION ALL SELECT r.device FROM operation o JOIN mdm_planning.scope_results r ON r.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND r.run=CASE WHEN o.snapshot->>'kind'='scope' THEN (o.snapshot->>'result')::uuid END WHERE r.matched
 ) SELECT device FROM targets WHERE device>coalesce(p_after,'') COLLATE "C" ORDER BY device COLLATE "C" LIMIT greatest(0,least(p_limit,65));
$$;

CREATE FUNCTION mdm_planning.scope_admission(p_scope uuid, p_device text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE s record; token record; head record; member record; tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 SELECT x.deleted,x.revision,x.resolution,r.phase,r.definition_revision,r.asset_watermark,r.input INTO s
 FROM mdm_planning.scopes x LEFT JOIN mdm_planning.scope_runs r ON(r.tenant_id,r.id)=(x.tenant_id,x.resolution)
 WHERE x.tenant_id=tenant AND x.id=p_scope FOR SHARE OF x;
 IF NOT FOUND OR s.deleted THEN RETURN jsonb_build_object('state','excluded'); END IF;
 IF s.phase IS DISTINCT FROM 'published' OR s.definition_revision IS DISTINCT FROM s.revision THEN RETURN jsonb_build_object('state','pending'); END IF;
 FOR token IN
  SELECT 'group-'||v.kind||'.'||(src->'reference'->>'id') AS id,(src->>v.field)::bigint AS revision
  FROM jsonb_array_elements(s.input->'sources') src
  CROSS JOIN (VALUES('definition','definitionVersion'),('members','memberVersion'),('authority','authorityVersion')) v(kind,field)
  WHERE src->'reference'->>'kind'='group' ORDER BY id
 LOOP
  SELECT h.revision,h.required_input,h.observed_input INTO head FROM mdm_planning.source_heads h WHERE h.tenant_id=tenant AND h.id=token.id FOR SHARE;
  IF NOT FOUND OR head.revision<>token.revision OR head.observed_input<head.required_input THEN RETURN jsonb_build_object('state','pending'); END IF;
  IF token.id LIKE 'group-members.%' AND EXISTS(
   SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=tenant AND c.revision>head.observed_input
   AND (p_device IS NULL OR c.identity->>'device'=p_device OR EXISTS(SELECT 1 FROM mdm_access.asset_authority_history h WHERE h.tenant_id=tenant AND h.kind='registration' AND h.identity=c.identity->>'registration' AND h.device=p_device))
   AND (c.kind IN('device','registration','source','credential') OR EXISTS(SELECT 1 FROM mdm_assets.group_fields f WHERE f.tenant_id=tenant AND f.group_id=substring(token.id FROM 15)::uuid AND f.field=ANY(c.fields)))
  ) THEN RETURN jsonb_build_object('state','pending'); END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM mdm_access.asset_authority_history h WHERE h.tenant_id=tenant AND (h.device=p_device OR (p_device IS NULL AND EXISTS(SELECT 1 FROM jsonb_array_elements(s.input->'sources') src WHERE src->'reference'->>'kind'='group' OR src->'reference'->>'id'=h.device))) AND h.revision>s.asset_watermark)
 OR EXISTS(SELECT 1 FROM mdm.asset_changes c WHERE c.tenant_id=tenant AND c.revision>s.asset_watermark AND (p_device IS NULL OR c.identity->>'device'=p_device OR EXISTS(SELECT 1 FROM mdm_access.asset_authority_history h WHERE h.tenant_id=tenant AND h.kind='registration' AND h.identity=c.identity->>'registration' AND h.device=p_device))
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(s.input->'sources') src JOIN mdm_assets.group_fields f ON f.tenant_id=tenant AND f.group_id=CASE WHEN src->'reference'->>'kind'='group' THEN (src->'reference'->>'id')::uuid END WHERE f.field=ANY(c.fields)))
 THEN RETURN jsonb_build_object('state','pending'); END IF;
 IF p_device IS NULL THEN RETURN jsonb_build_object('state','fresh'); END IF;
 SELECT m.matched,m.explanation,m.entry_revision INTO member FROM mdm_planning.scope_results m WHERE m.tenant_id=tenant AND m.run=s.resolution AND m.device=p_device;
 IF NOT FOUND THEN RETURN jsonb_build_object('state','excluded'); END IF;
 IF member.matched THEN RETURN jsonb_build_object('state','eligible','entry',member.entry_revision); END IF;
 IF member.explanation->'reasons' ?| ARRAY['unknown_target','unknown_limitation','unknown_exclusion'] THEN RETURN jsonb_build_object('state','pending'); END IF;
 RETURN jsonb_build_object('state','excluded');
END;
$$;

-- A narrow product read boundary preserves device-command's single runtime role.
CREATE FUNCTION mdm_commands.installation_status(p_operation uuid) RETURNS text
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 SELECT d.status FROM mdm_commands.operations o
 JOIN rss_device_command.commands d ON(d.tenant_id,d.command_id)=(o.tenant_id,o.id::text)
 WHERE o.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND o.id=p_operation AND o.request->'task'->>'kind'='agent_install';
$$;
REVOKE ALL ON FUNCTION mdm_commands.installation_status(uuid) FROM PUBLIC;

CREATE TABLE mdm_automation.automation_jobs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    kind text NOT NULL,
    target text NOT NULL,
    input jsonb NOT NULL,
    forwarded boolean DEFAULT false NOT NULL,
    completed boolean DEFAULT false NOT NULL,
    cursor text,
    replacement_task uuid,
    authority_revision bigint DEFAULT 0 NOT NULL,
    failure text,
    failure_detail jsonb,
    CONSTRAINT automation_jobs_authority_revision_check CHECK ((authority_revision >= 0)),
    CONSTRAINT automation_jobs_failure_check CHECK ((failure = ANY (ARRAY['superseded'::text, 'capacity_exceeded'::text, 'source_unavailable'::text, 'invalid_input'::text, 'storage_invariant'::text, 'automation_suspended'::text, 'configuration_target_limit'::text, 'capability_unknown'::text, 'platform_unsupported'::text, 'stale_plan'::text, 'owner_conflict'::text]))),
    CONSTRAINT automation_jobs_input_check CHECK ((octet_length((input)::text) <= 1048576)),
    CONSTRAINT automation_jobs_kind_check CHECK ((kind = ANY (ARRAY['group'::text, 'group_preview'::text, 'scope'::text, 'policy_reconcile'::text, 'asset_query'::text, 'compliance'::text]))),
    CONSTRAINT automation_jobs_target_check CHECK (((octet_length(target) >= 1) AND (octet_length(target) <= 256)))
);

ALTER TABLE ONLY mdm_automation.automation_jobs FORCE ROW LEVEL SECURITY;

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
    tenant_id uuid NOT NULL,
    device text NOT NULL,
    identifier text NOT NULL,
    profile uuid NOT NULL,
    operation uuid NOT NULL,
    registration uuid NOT NULL,
    version bigint NOT NULL,
    enabled boolean NOT NULL,
    CONSTRAINT profiles_version_check CHECK ((version > 0))
);

ALTER TABLE ONLY mdm_commands.apple_profiles FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.attempts (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    operation uuid NOT NULL,
    ordinal bigint NOT NULL,
    credential uuid NOT NULL,
    session bigint NOT NULL,
    message bigint NOT NULL,
    command bigint NOT NULL,
    phase text NOT NULL,
    uri text NOT NULL,
    status integer,
    value text,
    received_at bigint,
    receipt_accepted boolean,
    request bytea NOT NULL,
    CONSTRAINT attempts_ordinal_check CHECK ((ordinal > 0)),
    CONSTRAINT attempts_phase_check CHECK ((phase = ANY (ARRAY['prepare'::text, 'execute'::text, 'observe'::text]))),
    CONSTRAINT attempts_status_check CHECK (((status IS NULL) OR ((status >= 100) AND (status <= 599)))),
    CONSTRAINT attempts_value_check CHECK (((value IS NULL) OR (octet_length(value) <= 4096)))
);

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
    request jsonb NOT NULL,
    fingerprint bytea NOT NULL,
    registration uuid NOT NULL,
    registration_generation bigint NOT NULL,
    generation bigint NOT NULL,
    epoch bigint NOT NULL,
    approval jsonb NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    dispatch_fingerprint bytea NOT NULL,
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
    CONSTRAINT operations_request_check CHECK ((octet_length((request)::text) <= 4096)),
    CONSTRAINT operations_revision_check CHECK ((revision > 0)),
    CONSTRAINT operations_source_kind_check CHECK ((source_kind = ANY (ARRAY['direct'::text, 'policy'::text, 'remote_operation'::text])))
);

ALTER TABLE ONLY mdm_commands.operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_commands.policy_recovery (
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

CREATE TABLE mdm_flow.cursor_keys (
    tenant_id uuid NOT NULL,
    secret bytea NOT NULL,
    CONSTRAINT cursor_keys_secret_check CHECK ((octet_length(secret) = 32))
);

ALTER TABLE ONLY mdm_flow.cursor_keys FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.asset_dispatch (
    tenant_id uuid NOT NULL,
    consumed bigint DEFAULT 0 NOT NULL,
    watermark bigint DEFAULT 0 NOT NULL,
    cursor uuid,
    failure text,
    failure_generation bigint DEFAULT 0 NOT NULL,
    phase text DEFAULT 'groups'::text NOT NULL,
    CONSTRAINT asset_dispatch_check CHECK (((consumed >= 0) AND (watermark >= consumed))),
    CONSTRAINT asset_dispatch_failure_check CHECK ((failure = 'automation_suspended'::text)),
    CONSTRAINT asset_dispatch_failure_generation_check CHECK ((failure_generation >= 0)),
    CONSTRAINT asset_dispatch_phase_check CHECK ((phase = ANY (ARRAY['groups'::text, 'devices'::text, 'compliance'::text])))
);

ALTER TABLE ONLY mdm_planning.asset_dispatch FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.configuration_claims (
    tenant_id uuid NOT NULL,
    policy uuid NOT NULL,
    device text NOT NULL,
    version uuid NOT NULL,
    operation uuid
);

ALTER TABLE ONLY mdm_planning.configuration_claims FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.configuration_devices (
    tenant_id uuid NOT NULL,
    device text NOT NULL,
    input_revision bigint DEFAULT 1 NOT NULL,
    observed_revision bigint DEFAULT 0 NOT NULL,
    operation uuid,
    digest bytea,
    diagnosis text,
    CONSTRAINT configuration_devices_diagnosis_check CHECK ((diagnosis = ANY (ARRAY['waiting_scope'::text, 'waiting_registration'::text, 'waiting_capability'::text, 'not_applicable'::text, 'configuration_conflict'::text, 'removing'::text, 'unassigned'::text]))),
    CONSTRAINT configuration_devices_input_revision_check CHECK ((input_revision > 0)),
    CONSTRAINT configuration_devices_observed_revision_check CHECK ((observed_revision >= 0))
);

ALTER TABLE ONLY mdm_planning.configuration_devices FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.firewall_resources (
    tenant_id uuid NOT NULL,
    resource text NOT NULL,
    version text NOT NULL,
    enabled boolean NOT NULL,
    digest bytea NOT NULL,
    CONSTRAINT firewall_resources_digest_check CHECK ((octet_length(digest) = 32))
);

ALTER TABLE ONLY mdm_planning.firewall_resources FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    actor text NOT NULL,
    CONSTRAINT operations_actor_check CHECK ((length(actor) > 0)),
    CONSTRAINT operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT operations_response_check CHECK ((octet_length((response)::text) <= 8388608))
);

ALTER TABLE ONLY mdm_planning.operations FORCE ROW LEVEL SECURITY;

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
    CONSTRAINT remote_operations_frozen_check CHECK ((octet_length((frozen)::text) <= 1048576)),
    CONSTRAINT remote_operations_snapshot_check CHECK ((octet_length((snapshot)::text) <= 4194304))
);

ALTER TABLE ONLY mdm_planning.remote_operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.scope_results (
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    device text NOT NULL COLLATE pg_catalog."C",
    matched boolean NOT NULL,
    explanation jsonb NOT NULL,
    entry_revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT scope_results_entry_revision_check CHECK ((entry_revision >= 0)),
    CONSTRAINT scope_results_explanation_check CHECK ((octet_length((explanation)::text) <= 1048576))
);

ALTER TABLE ONLY mdm_planning.scope_results FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.scope_runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    scope uuid NOT NULL,
    definition_revision bigint NOT NULL,
    asset_watermark bigint NOT NULL,
    input jsonb NOT NULL,
    fingerprint bytea NOT NULL,
    identity_revision bigint DEFAULT 0 NOT NULL,
    previous_resolution uuid,
    semantic_changed boolean DEFAULT false NOT NULL,
    result_fingerprint bytea,
    phase text NOT NULL,
    source_index integer DEFAULT 0 NOT NULL,
    source_cursor text,
    evaluation_cursor text,
    object_count bigint DEFAULT 0 NOT NULL,
    member_count bigint DEFAULT 0 NOT NULL,
    CONSTRAINT scope_runs_check CHECK (((member_count >= 0) AND (member_count <= object_count))),
    CONSTRAINT scope_runs_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT scope_runs_identity_revision_check CHECK ((identity_revision >= 0)),
    CONSTRAINT scope_runs_input_check CHECK ((octet_length((input)::text) <= 1048576)),
    CONSTRAINT scope_runs_object_count_check CHECK (((object_count >= 0) AND (object_count <= 1000000))),
    CONSTRAINT scope_runs_phase_check CHECK ((phase = ANY (ARRAY['sources'::text, 'evaluate'::text, 'ready'::text, 'published'::text, 'superseded'::text]))),
    CONSTRAINT scope_runs_result_fingerprint_check CHECK (((result_fingerprint IS NULL) OR (octet_length(result_fingerprint) = 32))),
    CONSTRAINT scope_runs_source_index_check CHECK (((source_index >= 0) AND (source_index <= 1000)))
);

ALTER TABLE ONLY mdm_planning.scope_runs FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.scope_source_members (
    unknown boolean DEFAULT false NOT NULL,
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    source integer NOT NULL,
    device text NOT NULL COLLATE pg_catalog."C",
    CONSTRAINT scope_source_members_device_check CHECK (((octet_length(device) >= 1) AND (octet_length(device) <= 256))),
    CONSTRAINT scope_source_members_source_check CHECK (((source >= 0) AND (source <= 999)))
);

ALTER TABLE ONLY mdm_planning.scope_source_members FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.scope_sources (
    tenant_id uuid NOT NULL,
    scope uuid NOT NULL,
    kind text NOT NULL,
    target text NOT NULL,
    CONSTRAINT scope_sources_kind_check CHECK ((kind = ANY (ARRAY['group'::text, 'device'::text])))
);

ALTER TABLE ONLY mdm_planning.scope_sources FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.scope_versions (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL,
    definition jsonb NOT NULL,
    CONSTRAINT scope_versions_definition_check CHECK ((octet_length((definition)::text) <= 65536)),
    CONSTRAINT scope_versions_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY mdm_planning.scope_versions FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.scopes (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    calculation_revision bigint DEFAULT 0 NOT NULL,
    resolution uuid,
    resolution_revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT scopes_resolution_revision_check CHECK ((resolution_revision >= 0)),
    CONSTRAINT scopes_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY mdm_planning.scopes FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.source_heads (
    tenant_id uuid NOT NULL,
    id text NOT NULL,
    revision bigint NOT NULL,
    required_input bigint DEFAULT 0 NOT NULL,
    observed_input bigint DEFAULT 0 NOT NULL,
    CONSTRAINT source_heads_id_check CHECK (((octet_length(id) >= 1) AND (octet_length(id) <= 128))),
    CONSTRAINT source_heads_observed_input_check CHECK ((observed_input >= 0)),
    CONSTRAINT source_heads_required_input_check CHECK ((required_input >= 0)),
    CONSTRAINT source_heads_revision_check CHECK ((revision >= 0))
);

ALTER TABLE ONLY mdm_planning.source_heads FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_publication.operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    actor text NOT NULL,
    CONSTRAINT operations_actor_check CHECK ((length(actor) > 0)),
    CONSTRAINT operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT operations_response_check CHECK ((octet_length((response)::text) <= 8388608))
);

ALTER TABLE ONLY mdm_publication.operations FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_resource_catalog.operations (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    actor text NOT NULL,
    CONSTRAINT operations_actor_check CHECK ((length(actor) > 0)),
    CONSTRAINT operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT operations_response_check CHECK ((octet_length((response)::text) <= 8388608))
);

ALTER TABLE ONLY mdm_resource_catalog.operations FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_automation.automation_jobs
    ADD CONSTRAINT automation_jobs_pkey PRIMARY KEY (tenant_id, id);

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
    ADD CONSTRAINT profiles_pkey PRIMARY KEY (tenant_id, device);

ALTER TABLE ONLY mdm_commands.apple_profiles
    ADD CONSTRAINT profiles_tenant_id_identifier_key UNIQUE (tenant_id, identifier);

ALTER TABLE ONLY mdm_commands.requests
    ADD CONSTRAINT requests_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE ONLY mdm_flow.cursor_keys
    ADD CONSTRAINT cursor_keys_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY mdm_planning.asset_dispatch
    ADD CONSTRAINT asset_dispatch_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY mdm_planning.configuration_claims
    ADD CONSTRAINT configuration_claims_pkey PRIMARY KEY (tenant_id, policy, device);

ALTER TABLE ONLY mdm_planning.configuration_devices
    ADD CONSTRAINT configuration_devices_pkey PRIMARY KEY (tenant_id, device);

ALTER TABLE ONLY mdm_planning.firewall_resources
    ADD CONSTRAINT firewall_resources_pkey PRIMARY KEY (tenant_id, resource, version);

ALTER TABLE ONLY mdm_planning.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE ONLY mdm_planning.remote_operation_targets
    ADD CONSTRAINT remote_operation_targets_pkey PRIMARY KEY (tenant_id, operation, device);

ALTER TABLE ONLY mdm_planning.remote_operations
    ADD CONSTRAINT remote_operations_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_planning.scope_results
    ADD CONSTRAINT scope_results_pkey PRIMARY KEY (tenant_id, run, device);

ALTER TABLE ONLY mdm_planning.scope_runs
    ADD CONSTRAINT scope_runs_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_planning.scope_source_members
    ADD CONSTRAINT scope_source_members_pkey PRIMARY KEY (tenant_id, run, source, device);

ALTER TABLE ONLY mdm_planning.scope_sources
    ADD CONSTRAINT scope_sources_pkey PRIMARY KEY (tenant_id, scope, kind, target);

ALTER TABLE ONLY mdm_planning.scope_versions
    ADD CONSTRAINT scope_versions_pkey PRIMARY KEY (tenant_id, id, revision);

ALTER TABLE ONLY mdm_planning.scopes
    ADD CONSTRAINT scopes_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_planning.source_heads
    ADD CONSTRAINT source_heads_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_publication.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE ONLY mdm_resource_catalog.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, id);

CREATE INDEX automation_jobs_pending ON mdm_automation.automation_jobs USING btree (tenant_id, id) WHERE (NOT forwarded);

CREATE INDEX action_due ON mdm_commands.action_runs USING btree (tenant_id, registration, available_at, id);

CREATE INDEX action_runs_software_stage_latest ON mdm_commands.action_runs USING btree (tenant_id, policy_version, device, created_at DESC, id DESC);

CREATE INDEX native_session_receipts ON mdm_commands.attempts USING btree (tenant_id, session, operation) WHERE receipt_accepted;

CREATE UNIQUE INDEX remote_native_once ON mdm_commands.operations USING btree (tenant_id, remote_operation, device) WHERE (remote_operation IS NOT NULL);

CREATE INDEX scope_results_members ON mdm_planning.scope_results USING btree (tenant_id, run, device) WHERE matched;

CREATE INDEX scope_source_members_devices ON mdm_planning.scope_source_members USING btree (tenant_id, run, device, source);

CREATE INDEX scope_sources_target ON mdm_planning.scope_sources USING btree (tenant_id, kind, target, scope);

ALTER TABLE mdm_automation.automation_jobs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_automation.automation_jobs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

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

ALTER TABLE mdm_flow.cursor_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_flow.cursor_keys USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_planning.asset_dispatch ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.configuration_claims ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.configuration_devices ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.firewall_resources ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.remote_operation_targets ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.remote_operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_results ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_source_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_sources ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_versions ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scopes ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.source_heads ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_planning.asset_dispatch USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.configuration_claims USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.configuration_devices USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.firewall_resources USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.remote_operation_targets USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.remote_operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.scope_results USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.scope_runs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.scope_source_members USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.scope_sources USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.scope_versions USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.scopes USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_planning.source_heads USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_publication.operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_publication.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_resource_catalog.operations ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_resource_catalog.operations USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));
COMMIT;
