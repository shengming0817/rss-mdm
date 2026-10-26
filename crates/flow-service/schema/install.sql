-- Fresh installation: flow owns these objects.
BEGIN;
SET LOCAL check_function_bodies = false;

CREATE SCHEMA mdm_automation;

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

CREATE FUNCTION mdm_planning.group_current(p_group uuid) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
SELECT coalesce((SELECT NOT g.deleted AND
 (g.kind='static' AND g.member_set IS NULL OR b.phase='published' AND b.rule_version IS NOT DISTINCT FROM g.rule_version)
 FROM mdm_group.groups g LEFT JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(g.tenant_id,g.member_set)
 WHERE g.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND g.id=p_group),false);
$$;

CREATE FUNCTION mdm_planning.scope_admission(p_scope uuid, p_device text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; s record; token record;
BEGIN
 PERFORM FROM mdm_planning.scopes WHERE tenant_id=tenant AND id=p_scope FOR SHARE;
 RETURN mdm_planning.scope_state(p_scope,p_device);
END $$;

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
    CONSTRAINT automation_jobs_failure_check CHECK ((failure = ANY (ARRAY['superseded'::text, 'capacity_exceeded'::text, 'source_unavailable'::text, 'invalid_input'::text, 'storage_invariant'::text, 'automation_suspended'::text, 'configuration_target_limit'::text, 'capability_unknown'::text, 'platform_unsupported'::text, 'stale_plan'::text, 'owner_conflict'::text, 'permission_denied'::text]))),
    CONSTRAINT automation_jobs_input_check CHECK ((octet_length((input)::text) <= 1048576)),
    CONSTRAINT automation_jobs_kind_check CHECK ((kind = ANY (ARRAY['group'::text, 'group_preview'::text, 'group_definition'::text, 'scope'::text, 'policy_reconcile'::text, 'policy_event'::text, 'asset_query'::text, 'compliance'::text]))),
    CONSTRAINT automation_jobs_target_check CHECK (((octet_length(target) >= 1) AND (octet_length(target) <= 256)))
);

ALTER TABLE ONLY mdm_automation.automation_jobs FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_flow.cursor_keys (
    tenant_id uuid NOT NULL,
    secret bytea NOT NULL,
    CONSTRAINT cursor_keys_secret_check CHECK ((octet_length(secret) = 32))
);

ALTER TABLE ONLY mdm_flow.cursor_keys FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.asset_dispatch (
    relation_revision bigint DEFAULT 0 NOT NULL CHECK(relation_revision>=0),
    relation_cursor uuid, relation_pending_revision bigint,

    tenant_id uuid NOT NULL,
    consumed bigint DEFAULT 0 NOT NULL,
    watermark bigint DEFAULT 0 NOT NULL,
    cursor text COLLATE "C",
    failure text,
    failure_generation bigint DEFAULT 0 NOT NULL,
    phase text DEFAULT 'groups'::text NOT NULL,
    CONSTRAINT asset_dispatch_check CHECK (((consumed >= 0) AND (watermark >= consumed))),
    CONSTRAINT asset_dispatch_failure_check CHECK ((failure = 'automation_suspended'::text)),
    CONSTRAINT asset_dispatch_failure_generation_check CHECK ((failure_generation >= 0)),
    CONSTRAINT asset_dispatch_phase_check CHECK ((phase = ANY (ARRAY['groups'::text, 'devices'::text, 'scopes'::text, 'compliance'::text])))
);

ALTER TABLE ONLY mdm_planning.asset_dispatch FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.scope_results (
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    device text NOT NULL COLLATE pg_catalog."C",
    matched boolean NOT NULL,
    explanation jsonb NOT NULL,
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
    projection_cursor text,
    channel_hashes jsonb NOT NULL DEFAULT jsonb_build_object('agent',repeat('0',64),'mdm',repeat('0',64)),
    object_count bigint DEFAULT 0 NOT NULL,
    member_count bigint DEFAULT 0 NOT NULL,
    CONSTRAINT scope_runs_check CHECK (((member_count >= 0) AND (member_count <= object_count))),
    CONSTRAINT scope_runs_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT scope_runs_identity_revision_check CHECK ((identity_revision >= 0)),
    CONSTRAINT scope_runs_input_check CHECK ((octet_length((input)::text) <= 1048576)),
    CONSTRAINT scope_runs_object_count_check CHECK ((object_count >= 0)),
    CONSTRAINT scope_runs_phase_check CHECK ((phase = ANY (ARRAY['sources'::text, 'evaluate'::text, 'project'::text, 'ready'::text, 'published'::text, 'superseded'::text]))),
    CONSTRAINT scope_runs_result_fingerprint_check CHECK (((result_fingerprint IS NULL) OR (octet_length(result_fingerprint) = 32))),
    CONSTRAINT scope_runs_source_index_check CHECK (((source_index >= 0) AND (source_index <= 1000)))
);

ALTER TABLE ONLY mdm_planning.scope_runs FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_planning.scope_source_members (
    input jsonb NOT NULL,
    unknown boolean DEFAULT false NOT NULL,
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    source integer NOT NULL,
    device text NOT NULL COLLATE pg_catalog."C",
    CONSTRAINT scope_source_members_device_check CHECK (((octet_length(device) >= 1) AND (octet_length(device) <= 300))),
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
    agent_resolution_revision bigint NOT NULL DEFAULT 0 CHECK(agent_resolution_revision>=0),
    mdm_resolution_revision bigint NOT NULL DEFAULT 0 CHECK(mdm_resolution_revision>=0),
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

ALTER TABLE ONLY mdm_flow.cursor_keys
    ADD CONSTRAINT cursor_keys_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY mdm_planning.asset_dispatch
    ADD CONSTRAINT asset_dispatch_pkey PRIMARY KEY (tenant_id);

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

CREATE INDEX scope_results_members ON mdm_planning.scope_results USING btree (tenant_id, run, device) WHERE matched;

CREATE INDEX scope_source_members_devices ON mdm_planning.scope_source_members USING btree (tenant_id, run, device, source);

CREATE INDEX scope_sources_target ON mdm_planning.scope_sources USING btree (tenant_id, kind, target, scope);

ALTER TABLE mdm_automation.automation_jobs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_automation.automation_jobs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_flow.cursor_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_flow.cursor_keys USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE mdm_planning.asset_dispatch ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_results ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_source_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_sources ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scope_versions ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.scopes ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_planning.source_heads ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_planning.asset_dispatch USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

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


CREATE TABLE mdm_planning.event_batches (
 tenant_id uuid NOT NULL, id uuid NOT NULL, request uuid NOT NULL, actor text NOT NULL,
 caller jsonb NOT NULL, device text NOT NULL, input jsonb NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 created_at bigint NOT NULL, deadline bigint NOT NULL CHECK(deadline>created_at),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,actor,request)
);
CREATE TABLE mdm_planning.event_members (
 tenant_id uuid NOT NULL,batch uuid NOT NULL,id uuid NOT NULL,policy uuid NOT NULL,
 revision bigint NOT NULL,version uuid NOT NULL,target jsonb NOT NULL,authority jsonb NOT NULL,decision jsonb NOT NULL,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,batch,policy),
 FOREIGN KEY(tenant_id,batch) REFERENCES mdm_planning.event_batches(tenant_id,id)
);
CREATE INDEX event_members_pending ON mdm_planning.event_members(tenant_id,batch,id) WHERE decision->>'state'='pending';
CREATE INDEX event_batches_device ON mdm_planning.event_batches(tenant_id,device,id);
ALTER TABLE mdm_planning.event_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.event_batches FORCE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.event_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.event_members FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_planning.event_batches USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON mdm_planning.event_members USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_planning.event_batches TO mdm_flow_runtime,mdm_command_runtime;
GRANT SELECT,INSERT ON mdm_planning.event_members TO mdm_flow_runtime;
GRANT INSERT ON mdm_planning.event_members TO mdm_command_runtime;

COMMIT;

CREATE TABLE mdm_planning.scope_channel_results (
 tenant_id uuid NOT NULL,
 run uuid NOT NULL,
 channel text NOT NULL CHECK(channel IN('agent','mdm')),
 device text COLLATE "C" NOT NULL CHECK(octet_length(device)<=256),
 matched boolean NOT NULL,
 pending boolean NOT NULL,
 target jsonb NOT NULL CHECK(octet_length(target::text)<=1024),
 entry_revision bigint NOT NULL CHECK(entry_revision>=0),
 PRIMARY KEY(tenant_id,run,channel,device)
);
ALTER TABLE mdm_planning.scope_channel_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.scope_channel_results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_planning.scope_channel_results USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE INDEX scope_channel_results_cursor ON mdm_planning.scope_channel_results(tenant_id,run,((channel||':'||device) COLLATE "C"));
CREATE INDEX scope_source_members_channels ON mdm_planning.scope_source_members USING gin((input->'members') jsonb_path_ops);

CREATE FUNCTION mdm_planning.guard_scope_channel_result() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p text;
BEGIN
 SELECT phase INTO STRICT p FROM mdm_planning.scope_runs WHERE tenant_id=NEW.tenant_id AND id=NEW.run;
 IF p NOT IN('sources','project') THEN RAISE EXCEPTION 'scope channel result is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;$$;
REVOKE ALL ON FUNCTION mdm_planning.guard_scope_channel_result() FROM PUBLIC;
CREATE TRIGGER scope_channel_result_guard BEFORE INSERT OR UPDATE ON mdm_planning.scope_channel_results FOR EACH ROW EXECUTE FUNCTION mdm_planning.guard_scope_channel_result();

-- Only traversal state is additional; job input/cursor/terminal state remain in Automation.
CREATE TABLE mdm_planning.group_definition_walk (
 tenant_id uuid NOT NULL, task_id uuid NOT NULL, node_id uuid NOT NULL,
 graph_revision bigint NOT NULL CHECK(graph_revision>=0), visited boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,task_id,node_id)
);
CREATE INDEX group_definition_walk_pending ON mdm_planning.group_definition_walk(tenant_id,task_id,graph_revision,node_id) WHERE NOT visited;
ALTER TABLE mdm_planning.group_definition_walk ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_planning.group_definition_walk FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_planning.group_definition_walk
 USING(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=NULLIF(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT,DELETE ON mdm_planning.group_definition_walk TO mdm_flow_runtime;
GRANT UPDATE(graph_revision,visited) ON mdm_planning.group_definition_walk TO mdm_flow_runtime;
