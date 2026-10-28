-- Scope owns definitions, frozen inputs and collection results.
BEGIN;
SET LOCAL check_function_bodies=false;
CREATE SCHEMA mdm_scope;
REVOKE ALL ON SCHEMA mdm_scope FROM PUBLIC;
GRANT USAGE ON SCHEMA mdm_scope TO mdm_flow_runtime,mdm_access,mdm_command_runtime;

CREATE FUNCTION mdm_scope.scope_admission(p_scope uuid, p_device text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; s record; token record;
BEGIN
 PERFORM FROM mdm_scope.scopes WHERE tenant_id=tenant AND id=p_scope FOR SHARE;
 RETURN mdm_scope.scope_state(p_scope,p_device);
END $$;

CREATE TABLE mdm_scope.scope_results (
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    device text NOT NULL COLLATE pg_catalog."C",
    matched boolean NOT NULL,
    explanation jsonb NOT NULL,
    CONSTRAINT scope_results_explanation_check CHECK ((octet_length((explanation)::text) <= 1048576))
);

ALTER TABLE ONLY mdm_scope.scope_results FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_scope.scope_runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    scope uuid NOT NULL,
    definition_revision bigint NOT NULL,
    asset_watermark bigint NOT NULL,
    input jsonb NOT NULL,
    fingerprint bytea NOT NULL,
    phase text NOT NULL,
    source_index integer DEFAULT 0 NOT NULL,
    source_cursor text,
    evaluation_cursor text,
    object_count bigint DEFAULT 0 NOT NULL,
    member_count bigint DEFAULT 0 NOT NULL,
    CONSTRAINT scope_runs_check CHECK (((member_count >= 0) AND (member_count <= object_count))),
    CONSTRAINT scope_runs_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT scope_runs_input_check CHECK ((octet_length((input)::text) <= 1048576)),
    CONSTRAINT scope_runs_object_count_check CHECK ((object_count >= 0)),
    CONSTRAINT scope_runs_phase_check CHECK ((phase = ANY (ARRAY['sources'::text, 'evaluate'::text, 'project'::text, 'ready'::text, 'published'::text, 'superseded'::text]))),
    CONSTRAINT scope_runs_source_index_check CHECK (((source_index >= 0) AND (source_index <= 1000)))
);

ALTER TABLE ONLY mdm_scope.scope_runs FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_scope.scope_source_members (
    input jsonb NOT NULL,
    unknown boolean DEFAULT false NOT NULL,
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    source integer NOT NULL,
    device text NOT NULL COLLATE pg_catalog."C",
    CONSTRAINT scope_source_members_device_check CHECK (((octet_length(device) >= 1) AND (octet_length(device) <= 300))),
    CONSTRAINT scope_source_members_source_check CHECK (((source >= 0) AND (source <= 999)))
);

ALTER TABLE ONLY mdm_scope.scope_source_members FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_scope.scope_sources (
    tenant_id uuid NOT NULL,
    scope uuid NOT NULL,
    kind text NOT NULL,
    target text NOT NULL,
    CONSTRAINT scope_sources_kind_check CHECK ((kind = ANY (ARRAY['group'::text, 'device'::text])))
);

ALTER TABLE ONLY mdm_scope.scope_sources FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_scope.scope_versions (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL,
    definition jsonb NOT NULL,
    CONSTRAINT scope_versions_definition_check CHECK ((octet_length((definition)::text) <= 65536)),
    CONSTRAINT scope_versions_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY mdm_scope.scope_versions FORCE ROW LEVEL SECURITY;

CREATE TABLE mdm_scope.scopes (
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

ALTER TABLE ONLY mdm_scope.scopes FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY mdm_scope.scope_results
    ADD CONSTRAINT scope_results_pkey PRIMARY KEY (tenant_id, run, device);

ALTER TABLE ONLY mdm_scope.scope_runs
    ADD CONSTRAINT scope_runs_pkey PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY mdm_scope.scope_source_members
    ADD CONSTRAINT scope_source_members_pkey PRIMARY KEY (tenant_id, run, source, device);

ALTER TABLE ONLY mdm_scope.scope_sources
    ADD CONSTRAINT scope_sources_pkey PRIMARY KEY (tenant_id, scope, kind, target);

ALTER TABLE ONLY mdm_scope.scope_versions
    ADD CONSTRAINT scope_versions_pkey PRIMARY KEY (tenant_id, id, revision);

ALTER TABLE ONLY mdm_scope.scopes
    ADD CONSTRAINT scopes_pkey PRIMARY KEY (tenant_id, id);

CREATE INDEX scope_results_members ON mdm_scope.scope_results USING btree (tenant_id, run, device) WHERE matched;

CREATE INDEX scope_source_members_devices ON mdm_scope.scope_source_members USING btree (tenant_id, run, device, source);

CREATE INDEX scope_sources_target ON mdm_scope.scope_sources USING btree (tenant_id, kind, target, scope);

ALTER TABLE mdm_scope.scope_results ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_scope.scope_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_scope.scope_source_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_scope.scope_sources ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_scope.scope_versions ENABLE ROW LEVEL SECURITY;

ALTER TABLE mdm_scope.scopes ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON mdm_scope.scope_results USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_scope.scope_runs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_scope.scope_source_members USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_scope.scope_sources USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_scope.scope_versions USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON mdm_scope.scopes USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE INDEX scope_source_members_channels ON mdm_scope.scope_source_members USING gin((input->'members') jsonb_path_ops);

-- Lock-free owner kernels shared by query projections and locked admission.
CREATE FUNCTION mdm_scope.scope_state(p_scope uuid, p_device text) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE s record; token record; head record; member record; tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 SELECT x.deleted,x.revision,x.resolution,r.phase,r.definition_revision,r.asset_watermark,r.input INTO s
 FROM mdm_scope.scopes x LEFT JOIN mdm_scope.scope_runs r ON(r.tenant_id,r.id)=(x.tenant_id,x.resolution)
 WHERE x.tenant_id=tenant AND x.id=p_scope;
 IF NOT FOUND OR s.deleted THEN RETURN jsonb_build_object('state','excluded'); END IF;
 IF s.phase IS DISTINCT FROM 'published' OR s.definition_revision IS DISTINCT FROM s.revision THEN RETURN jsonb_build_object('state','pending'); END IF;
 -- Only explicit definition changes invalidate a complete publication.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(s.input->'sources') src
 LEFT JOIN mdm_group.groups g ON g.tenant_id=tenant AND g.id=CASE WHEN src->'reference'->>'kind'='group' THEN (src->'reference'->>'id')::uuid END
 LEFT JOIN mdm_group.source_state h ON h.tenant_id=tenant AND h.group_id=g.id
 WHERE src->'reference'->>'kind'='group' AND (g.id IS NULL OR g.deleted OR h.definition_version IS DISTINCT FROM (src->'coordinates'->>'definitionVersion')::bigint))
 THEN RETURN jsonb_build_object('state','pending'); END IF;
 RETURN jsonb_build_object('state','fresh');
END;
$$;

REVOKE ALL ON FUNCTION mdm_scope.scope_state(uuid,text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION mdm_scope.scope_state(uuid,text) TO mdm_access,mdm_flow_runtime,mdm_command_runtime;
CREATE TABLE mdm_scope.tasks (
 tenant_id uuid NOT NULL,id uuid NOT NULL,scope uuid NOT NULL,
 completed boolean NOT NULL DEFAULT false,failure text,failure_detail jsonb,replacement_task uuid,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,scope) REFERENCES mdm_scope.scopes(tenant_id,id),
 CHECK(failure IS NULL OR failure IN('superseded','capacity_exceeded','source_unavailable','invalid_input','storage_invariant','automation_suspended','permission_denied'))
);
CREATE UNIQUE INDEX scope_pending_task ON mdm_scope.tasks(tenant_id,scope) WHERE NOT completed;
ALTER TABLE mdm_scope.tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_scope.tasks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_scope.tasks USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE mdm_scope.asset_dispatch (
 tenant_id uuid PRIMARY KEY, consumed bigint NOT NULL DEFAULT 0 CHECK(consumed>=0),
 watermark bigint NOT NULL DEFAULT 0 CHECK(watermark>=consumed), cursor uuid
);
ALTER TABLE mdm_scope.asset_dispatch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_scope.asset_dispatch FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON mdm_scope.asset_dispatch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON mdm_scope.tasks,mdm_scope.asset_dispatch TO mdm_flow_runtime;
GRANT UPDATE(completed,failure,failure_detail,replacement_task) ON mdm_scope.tasks TO mdm_flow_runtime;
GRANT UPDATE(consumed,watermark,cursor) ON mdm_scope.asset_dispatch TO mdm_flow_runtime;
COMMIT;
