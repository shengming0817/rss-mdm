//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub install: &'static str,
    pub relations: &'static str,
    pub group_changes: &'static str,
    pub projections: &'static str,
    pub projection_relations: &'static str,
    pub projection_admission: &'static str,
    pub group_reference_facts: &'static str,
    pub group_blocker_facts: &'static str,
    pub admission: &'static str,
    pub configuration_admission: &'static str,
    pub access_admission: &'static str,
    pub authority_admission: &'static str,
    pub lib_accept_group_change_in_1: &'static str,
    pub lib_group_change_page_in_1: &'static str,
    pub lib_group_change_page_in_2: &'static str,
    pub lib_complete_group_change_page_in_1: &'static str,
    pub lib_target_members_in_1: &'static str,
    pub store_head_in_1: &'static str,
    pub store_head_in_2: &'static str,
    pub store_put_in_1: &'static str,
    pub store_put_in_2: &'static str,
    pub store_put_in_3: &'static str,
    pub store_retire_in: &'static str,
    pub store_owned_in: &'static str,
    pub store_owner_in: &'static str,
    pub store_replace_sources_in_1: &'static str,
    pub store_replace_sources_in_2: &'static str,
    pub store_create_run_in_1: &'static str,
    pub store_run_in_1: &'static str,
    pub store_stage_sources_in_1: &'static str,
    pub store_stage_sources_in_2: &'static str,
    pub store_phase_in_1: &'static str,
    pub store_publish_in_1: &'static str,
    pub store_publish_in_2: &'static str,
    pub store_publish_in_3: &'static str,
    pub store_definition_at_1: &'static str,
    pub store_enqueue_in_1: &'static str,
    pub store_enqueue_in_2: &'static str,
    pub store_request_inputs: &'static str,
    pub store_covered_inputs: &'static str,
    pub store_uncovered_inputs: &'static str,
    pub store_task_in_1: &'static str,
    pub store_finish_task_in_1: &'static str,
    pub store_replace_task_in_1: &'static str,
    pub store_evaluate_page_in_1: &'static str,
    pub store_evaluate_page_in_2: &'static str,
    pub store_evaluate_page_in_3: &'static str,
    pub store_asset_page_in_1: &'static str,
    pub store_asset_page_in_2: &'static str,
    pub store_asset_page_in_3: &'static str,
    pub store_asset_page_in_4: &'static str,
    pub store_asset_page_in_5: &'static str,
    pub store_complete_asset_page_in_1: &'static str,
    pub store_input_failed: &'static str,
    pub store_set_input_failed: &'static str,
    pub store_inputs_pending_in_1: &'static str,
    pub store_relation_window_in_1: &'static str,
    pub store_relation_window_in_2: &'static str,
    pub store_relation_targets_in_1: &'static str,
    pub store_complete_relation_page_in_1: &'static str,
    pub state_admission_on_1: &'static str,
    pub state_state_on_1: &'static str,
    pub authority_verify_authority_1: &'static str,
    pub authority_verify_authority_2: &'static str,
    pub authority_verify_authority_3: &'static str,
    pub group_change_admission: &'static str,
    pub object_manifest: &'static str,
    pub access_contract: &'static str,
    pub operation_lock: &'static str,
    pub operation_replay: &'static str,
    pub operation_receipt: &'static str,
    pub queue_counts: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $schema:literal, $schema_decl:literal, $schema_name:literal, $access_schema:literal, $access:literal, $tasks:literal, $tasks_name:literal, $asset_dispatch:literal, $asset_dispatch_name:literal, $group_changes:literal, $group_changes_name:literal, $owner:literal, $command_runtime:literal, $inventory_runtime:literal, $scope_runtime:literal, $policy_runtime:literal, $telemetry_runtime:literal, $scope_admission_header:literal, $scope_state_header:literal, $channel_admission_header:literal, $create_mdm_scope:literal, $role_mdm_identity_runtime:literal, $role_mdm_resource_runtime:literal, $role_mdm_software_runtime:literal, $object_qualification:literal, $index_26:literal, $index_27:literal, $index_28:literal, $index_29:literal, $index_30:literal, $index_31:literal, $index_32:literal, $index_33:literal, $index_34:literal, $index_35:literal, $index_36:literal, $index_37:literal, $index_38:literal, $index_39:literal, $index_40:literal, $index_41:literal, $index_42:literal, $index_43:literal, $index_44:literal, $access_contract_external_relations:literal, $operations:literal, $operations_name:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                install: concat!(r###"-- Scope owns definitions, frozen inputs and collection results.
BEGIN;
SET LOCAL check_function_bodies=false;
"###, $create_mdm_scope, r###";
REVOKE ALL ON "###, $schema_decl, r###" FROM PUBLIC;
GRANT USAGE ON "###, $schema_decl, " TO ", $scope_runtime, ",", $access, ",", $command_runtime, r###";

"###, $scope_admission_header, r###"p_scope uuid, p_device uuid) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; expected bigint; actual bigint; refs uuid[]; after_refs uuid[];
BEGIN
 SELECT revision INTO expected FROM "###, $schema, r###"scopes WHERE tenant_id=tenant AND id=p_scope;
 WITH RECURSIVE refs(id) AS (
  SELECT target::uuid FROM "###, $schema, r###"scope_sources WHERE tenant_id=tenant AND scope=p_scope AND kind='group'
  UNION SELECT child FROM refs x CROSS JOIN LATERAL mdm_group.scope_dependencies(x.id) child
 ) SELECT coalesce(array_agg(id ORDER BY id),ARRAY[]::uuid[]) INTO refs FROM refs;
 PERFORM mdm_group.lock_scope_dependencies(refs);
 -- Consumers can already hold their own reconcile target. A concurrent Scope
 -- publisher must not be waited on from that lock; RSS retries the whole attempt.
 PERFORM FROM "###, $schema, r###"scopes WHERE tenant_id=tenant AND id=p_scope FOR SHARE NOWAIT;
 SELECT revision INTO actual FROM "###, $schema, r###"scopes WHERE tenant_id=tenant AND id=p_scope;
 WITH RECURSIVE refs(id) AS (
  SELECT target::uuid FROM "###, $schema, r###"scope_sources WHERE tenant_id=tenant AND scope=p_scope AND kind='group'
  UNION SELECT child FROM refs x CROSS JOIN LATERAL mdm_group.scope_dependencies(x.id) child
 ) SELECT coalesce(array_agg(id ORDER BY id),ARRAY[]::uuid[]) INTO after_refs FROM refs;
 IF actual IS DISTINCT FROM expected OR after_refs IS DISTINCT FROM refs THEN RETURN jsonb_build_object('state','pending'); END IF;
 RETURN "###, $schema, r###"scope_state(p_scope,p_device);
END $$;

CREATE TABLE "###, $schema, r###"scope_results (
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    object_kind smallint NOT NULL CHECK(object_kind IN(0,1)), object_id uuid NOT NULL CHECK(object_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    matched boolean NOT NULL,
    explanation jsonb NOT NULL,
    CONSTRAINT scope_results_explanation_check CHECK ((octet_length((explanation)::text) <= 1048576))
);

ALTER TABLE ONLY "###, $schema, r###"scope_results FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $schema, r###"scope_runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    scope uuid NOT NULL,
    definition_revision bigint NOT NULL,
    covered_inputs bigint NOT NULL DEFAULT 0 CHECK(covered_inputs>=0),
    asset_cut jsonb NOT NULL,
    input jsonb NOT NULL,
    fingerprint bytea NOT NULL,
    phase text NOT NULL,
    source_index integer DEFAULT 0 NOT NULL,
    source_cursor_kind smallint CHECK(source_cursor_kind IN(0,1)), source_cursor uuid,
    evaluation_cursor_kind smallint CHECK(evaluation_cursor_kind IN(0,1)), evaluation_cursor uuid,
    CHECK((source_cursor_kind IS NULL)=(source_cursor IS NULL)),
    CHECK((evaluation_cursor_kind IS NULL)=(evaluation_cursor IS NULL)),
    object_count bigint DEFAULT 0 NOT NULL,
    member_count bigint DEFAULT 0 NOT NULL,
    CONSTRAINT scope_runs_check CHECK (((member_count >= 0) AND (member_count <= object_count))),
    CONSTRAINT scope_runs_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT scope_runs_input_check CHECK ((octet_length((input)::text) <= 1048576)),
    CONSTRAINT scope_runs_object_count_check CHECK ((object_count >= 0)),
    CONSTRAINT scope_runs_phase_check CHECK ((phase = ANY (ARRAY['sources'::text, 'evaluate'::text, 'project'::text, 'ready'::text, 'published'::text, 'superseded'::text]))),
    CONSTRAINT scope_runs_source_index_check CHECK (((source_index >= 0) AND (source_index <= 1000)))
);

ALTER TABLE ONLY "###, $schema, r###"scope_runs FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $schema, r###"scope_source_members (
    input jsonb NOT NULL,
    unknown boolean DEFAULT false NOT NULL,
    tenant_id uuid NOT NULL,
    run uuid NOT NULL,
    source integer NOT NULL,
    object_kind smallint NOT NULL CHECK(object_kind IN(0,1)), object_id uuid NOT NULL CHECK(object_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT scope_source_members_source_check CHECK (((source >= 0) AND (source <= 999)))
);

ALTER TABLE ONLY "###, $schema, r###"scope_source_members FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $schema, r###"scope_sources (
    tenant_id uuid NOT NULL,
    scope uuid NOT NULL,
    kind text NOT NULL,
    target uuid NOT NULL,
    CONSTRAINT scope_sources_kind_check CHECK ((kind = ANY (ARRAY['group'::text, 'device'::text])))
);

ALTER TABLE ONLY "###, $schema, r###"scope_sources FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $schema, r###"scope_versions (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL,
    definition jsonb NOT NULL,
    CONSTRAINT scope_versions_definition_check CHECK ((octet_length((definition)::text) <= 65536)),
    CONSTRAINT scope_versions_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY "###, $schema, r###"scope_versions FORCE ROW LEVEL SECURITY;

CREATE TABLE "###, $schema, r###"scopes (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    policy_id uuid NOT NULL CHECK (policy_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    stage_id uuid CHECK (stage_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    UNIQUE NULLS NOT DISTINCT (tenant_id,policy_id,stage_id),
    revision bigint NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    calculation_revision bigint DEFAULT 0 NOT NULL,
    input_revision bigint NOT NULL DEFAULT 0 CHECK(input_revision>=0),
    input_epoch uuid,input_xid xid8,
    CHECK((input_revision=0)=(input_epoch IS NULL AND input_xid IS NULL)),
    resolution uuid,
    resolution_revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT scopes_resolution_revision_check CHECK ((resolution_revision >= 0)),
    CONSTRAINT scopes_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY "###, $schema, r###"scopes FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY "###, $schema, r###"scope_results
    "###, $index_26, r###" PRIMARY KEY (tenant_id, run, object_kind, object_id);

ALTER TABLE ONLY "###, $schema, r###"scope_runs
    "###, $index_27, r###" PRIMARY KEY (tenant_id, id);

ALTER TABLE ONLY "###, $schema, r###"scope_source_members
    "###, $index_28, r###" PRIMARY KEY (tenant_id, run, source, object_kind, object_id);

ALTER TABLE ONLY "###, $schema, r###"scope_sources
    "###, $index_29, r###" PRIMARY KEY (tenant_id, scope, kind, target);

ALTER TABLE ONLY "###, $schema, r###"scope_versions
    "###, $index_30, r###" PRIMARY KEY (tenant_id, id, revision);

ALTER TABLE ONLY "###, $schema, r###"scopes
    "###, $index_31, r###" PRIMARY KEY (tenant_id, id);

"###, $index_32, " ON ", $schema, r###"scope_results USING btree (tenant_id, run, object_kind, object_id) WHERE matched;

"###, $index_33, " ON ", $schema, r###"scope_source_members USING btree (tenant_id, run, object_kind, object_id, source);

"###, $index_34, " ON ", $schema, r###"scope_sources USING btree (tenant_id, kind, target, scope);

ALTER TABLE "###, $schema, r###"scope_results ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $schema, r###"scope_runs ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $schema, r###"scope_source_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $schema, r###"scope_sources ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $schema, r###"scope_versions ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $schema, r###"scopes ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $schema, r###"scope_results USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $schema, r###"scope_runs USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $schema, r###"scope_source_members USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $schema, r###"scope_sources USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $schema, r###"scope_versions USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE POLICY tenant ON "###, $schema, r###"scopes USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

"###, $index_35, " ON ", $schema, r###"scope_source_members USING gin((input->'members') jsonb_path_ops);

-- Lock-free owner kernels shared by query projections and locked admission.
"###, $scope_state_header, r###"p_scope uuid, p_device uuid) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
DECLARE s record; token record; head record; member record; tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 SELECT x.deleted,x.revision,x.resolution,r.phase,r.definition_revision,r.asset_cut,r.input INTO s
 FROM "###, $schema, "scopes x LEFT JOIN ", $schema, r###"scope_runs r ON(r.tenant_id,r.id)=(x.tenant_id,x.resolution)
 WHERE x.tenant_id=tenant AND x.id=p_scope;
 IF NOT FOUND OR s.deleted THEN RETURN jsonb_build_object('state','excluded'); END IF;
 IF s.phase IS DISTINCT FROM 'published' OR s.definition_revision IS DISTINCT FROM s.revision THEN RETURN jsonb_build_object('state','pending'); END IF;
 -- Only explicit definition changes invalidate a complete publication.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(s.input->'sources') src
 LEFT JOIN LATERAL mdm_group.scope_source(CASE WHEN src->'reference'->>'kind'='group' THEN (src->'reference'->>'id')::uuid END) g ON true
 WHERE src->'reference'->>'kind'='group' AND (g.id IS NULL OR g.deleted OR g.definition_version IS DISTINCT FROM (src->'coordinates'->>'definitionVersion')::bigint))
 THEN RETURN jsonb_build_object('state','pending'); END IF;
 RETURN jsonb_build_object('state','fresh');
END;
$$;

REVOKE ALL ON FUNCTION "###, $schema, r###"scope_state(uuid,uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION "###, $schema, "scope_state(uuid,uuid) TO ", $access, ",", $scope_runtime, ",", $policy_runtime, ",", $inventory_runtime, ",", $telemetry_runtime, ",", $command_runtime, r###";
CREATE TABLE "###, $tasks, r###" (
 tenant_id uuid NOT NULL,id uuid NOT NULL,scope uuid NOT NULL,
 completed boolean NOT NULL DEFAULT false,failure text,failure_detail jsonb,replacement_task uuid,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,scope) REFERENCES "###, $schema, r###"scopes(tenant_id,id),
 CHECK(failure IS NULL OR failure IN('superseded','capacity_exceeded','source_unavailable','invalid_input','storage_invariant','automation_suspended','permission_denied'))
);
"###, $index_36, " ON ", $tasks, r###"(tenant_id,scope) WHERE NOT completed;
ALTER TABLE "###, $tasks, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $tasks, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $tasks, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE "###, $asset_dispatch, r###" (
 tenant_id uuid PRIMARY KEY, from_cut jsonb, to_cut jsonb,
 input_failed boolean NOT NULL DEFAULT false,
 event_after bigint NOT NULL DEFAULT 0 CHECK(event_after>=0),
 page_through bigint CHECK(page_through>event_after), cursor uuid,
 relation_consumed bigint NOT NULL DEFAULT 0 CHECK(relation_consumed>=0),
 relation_watermark bigint NOT NULL DEFAULT 0 CHECK(relation_watermark>=relation_consumed), relation_position bigint NOT NULL DEFAULT 0 CHECK(relation_position>=relation_consumed), relation_cursor uuid
);
ALTER TABLE "###, $asset_dispatch, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $asset_dispatch, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $asset_dispatch, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $tasks, ",", $asset_dispatch, " TO ", $scope_runtime, r###";
GRANT UPDATE(completed,failure,failure_detail,replacement_task) ON "###, $tasks, " TO ", $scope_runtime, r###";
GRANT UPDATE(input_failed,from_cut,to_cut,event_after,page_through,cursor,relation_consumed,relation_watermark,relation_position,relation_cursor) ON "###, $asset_dispatch, " TO ", $scope_runtime, r###";
CREATE TABLE "###, $operations, r###" (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    response jsonb NOT NULL,
    actor text NOT NULL,
    instance uuid NOT NULL,
    CONSTRAINT operations_actor_check CHECK ((length(actor) > 0)),
    CONSTRAINT operations_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT operations_response_check CHECK ((octet_length((response)::text) <= 8388608))
);

ALTER TABLE ONLY "###, $operations, r###" FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY "###, $operations, r###"
    ADD CONSTRAINT operations_pkey PRIMARY KEY (tenant_id, actor, id);

ALTER TABLE "###, $operations, r###" ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $operations, r###" USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));


COMMIT;

"###),
                relations: concat!(r###"BEGIN;
ALTER TABLE ONLY "###, $schema, r###"scope_results
    "###, $index_37, " FOREIGN KEY (tenant_id, run) REFERENCES ", $schema, r###"scope_runs(tenant_id, id);

ALTER TABLE ONLY "###, $schema, r###"scope_runs
    "###, $index_38, " FOREIGN KEY (tenant_id, scope) REFERENCES ", $schema, r###"scopes(tenant_id, id);

ALTER TABLE ONLY "###, $schema, r###"scope_source_members
    "###, $index_39, " FOREIGN KEY (tenant_id, run) REFERENCES ", $schema, r###"scope_runs(tenant_id, id);

ALTER TABLE ONLY "###, $schema, r###"scope_sources
    "###, $index_40, " FOREIGN KEY (tenant_id, scope) REFERENCES ", $schema, r###"scopes(tenant_id, id);

ALTER TABLE ONLY "###, $schema, r###"scope_versions
    "###, $index_41, " FOREIGN KEY (tenant_id, id) REFERENCES ", $schema, r###"scopes(tenant_id, id);

ALTER TABLE ONLY "###, $schema, r###"scopes
    "###, $index_42, " FOREIGN KEY (tenant_id, resolution) REFERENCES ", $schema, r###"scope_runs(tenant_id, id);

REVOKE ALL ON FUNCTION "###, $schema, r###"scope_admission(p_scope uuid, p_device uuid) FROM PUBLIC;

GRANT ALL ON FUNCTION "###, $schema, "scope_admission(p_scope uuid, p_device uuid) TO ", $command_runtime, r###";

GRANT ALL ON FUNCTION "###, $schema, "scope_admission(p_scope uuid, p_device uuid) TO ", $scope_runtime, ",", $policy_runtime, ",", $inventory_runtime, ",", $telemetry_runtime, r###";

GRANT SELECT,INSERT ON TABLE "###, $schema, "scope_results TO ", $scope_runtime, r###";

GRANT SELECT ON TABLE "###, $schema, "scope_results TO ", $command_runtime, r###";

GRANT SELECT,INSERT ON TABLE "###, $schema, "scope_runs TO ", $scope_runtime, r###";





GRANT UPDATE(phase) ON TABLE "###, $schema, "scope_runs TO ", $scope_runtime, r###";

GRANT UPDATE(source_index) ON TABLE "###, $schema, "scope_runs TO ", $scope_runtime, r###";

GRANT UPDATE(source_cursor) ON TABLE "###, $schema, "scope_runs TO ", $scope_runtime, r###";

GRANT UPDATE(evaluation_cursor) ON TABLE "###, $schema, "scope_runs TO ", $scope_runtime, r###";

GRANT UPDATE(object_count) ON TABLE "###, $schema, "scope_runs TO ", $scope_runtime, r###";

GRANT UPDATE(member_count) ON TABLE "###, $schema, "scope_runs TO ", $scope_runtime, r###";

GRANT SELECT,INSERT ON TABLE "###, $schema, "scope_source_members TO ", $scope_runtime, r###";

GRANT SELECT ON TABLE "###, $schema, "scope_source_members TO ", $command_runtime, r###";

GRANT SELECT ON TABLE "###, $schema, "scope_runs TO ", $command_runtime, r###";

GRANT SELECT ON TABLE "###, $schema, "scope_sources TO ", $scope_runtime, r###";

GRANT SELECT ON TABLE "###, $schema, "scope_versions TO ", $scope_runtime, r###";

GRANT SELECT ON TABLE "###, $schema, "scopes TO ", $scope_runtime, r###";

GRANT SELECT ON TABLE "###, $schema, "scopes TO ", $command_runtime, r###";



GRANT UPDATE(calculation_revision,input_revision,input_epoch,input_xid) ON TABLE "###, $schema, "scopes TO ", $scope_runtime, r###";

GRANT UPDATE(resolution) ON TABLE "###, $schema, "scopes TO ", $scope_runtime, r###";

GRANT UPDATE(resolution_revision) ON TABLE "###, $schema, "scopes TO ", $scope_runtime, r###";

GRANT EXECUTE ON FUNCTION "###, $schema, "scope_admission(uuid,uuid) TO ", $access, r###";




GRANT SELECT ON "###, $schema, "scopes,", $schema, "scope_runs,", $schema, "scope_source_members TO ", $access, r###";
GRANT SELECT ON "###, $operations, " TO ", $scope_runtime, r###";
-- Policy is the sole configuration writer; calculation stays on the Scope runtime.
GRANT USAGE ON "###, $schema_decl, " TO ", $policy_runtime, r###";
GRANT SELECT,INSERT ON "###, $schema, "scopes,", $schema, "scope_versions,", $schema, "scope_sources,", $tasks, ",", $operations, " TO ", $policy_runtime, r###";
GRANT UPDATE(revision,deleted,input_revision,input_epoch,input_xid) ON "###, $schema, "scopes TO ", $policy_runtime, r###";
GRANT DELETE ON "###, $schema, "scope_sources TO ", $policy_runtime, r###";
GRANT SELECT ON "###, $schema, "scope_runs TO ", $policy_runtime, r###";
GRANT UPDATE(phase) ON "###, $schema, "scope_runs TO ", $policy_runtime, r###";
GRANT UPDATE(completed,failure,failure_detail,replacement_task) ON "###, $tasks, " TO ", $policy_runtime, r###";
COMMIT;

GRANT USAGE ON "###, $schema_decl, " TO ", $inventory_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
GRANT SELECT ON "###, $schema, "scopes,", $schema, "scope_versions,", $schema, "scope_runs,", $schema, "scope_sources,", $schema, "scope_source_members,", $schema, "scope_results TO ", $inventory_runtime, ",", $policy_runtime, ",", $telemetry_runtime, r###";
"###),
                group_changes: concat!(r###"
REVOKE ALL ON "###, $schema_decl, r###" FROM PUBLIC;
CREATE TABLE "###, $group_changes, r###" (
 tenant_id uuid NOT NULL,event_id text NOT NULL CHECK(octet_length(event_id) BETWEEN 1 AND 256),
 group_id uuid NOT NULL,cursor uuid,completed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,event_id)
);
"###, $index_43, " ON ", $group_changes, r###"(tenant_id,event_id) WHERE NOT completed;
ALTER TABLE "###, $group_changes, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $group_changes, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $group_changes, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
REVOKE ALL ON "###, $group_changes, r###" FROM PUBLIC;
GRANT USAGE ON "###, $schema_decl, " TO mdm_scope_group_consumer,", $scope_runtime, r###";
GRANT SELECT,INSERT ON "###, $group_changes, r###" TO mdm_scope_group_consumer;
GRANT SELECT ON "###, $group_changes, " TO ", $scope_runtime, r###";
GRANT UPDATE(cursor,completed) ON "###, $group_changes, " TO ", $scope_runtime, r###";
GRANT SELECT,INSERT ON rss_transactional_messaging.consumer_dead_letter TO mdm_scope_group_consumer;
"###),
                projections: concat!(r###"-- Scope owns channel projections, qualification and entry continuity.
BEGIN;
SET LOCAL check_function_bodies=false;
CREATE TABLE "###, $schema, r###"scope_projection_runs (
 tenant_id uuid NOT NULL,id uuid NOT NULL,scope uuid NOT NULL,previous_resolution uuid,next_entry bigint NOT NULL CHECK(next_entry>0),
 phase text NOT NULL CHECK(phase IN('sources','project','ready','published')),
 source_cursor_source integer CHECK(source_cursor_source BETWEEN 0 AND 999),source_cursor_kind smallint CHECK(source_cursor_kind IN(0,1)), source_cursor uuid,projection_cursor_channel text CHECK(projection_cursor_channel IN('agent','mdm')), projection_cursor uuid,
 CHECK((source_cursor_source IS NULL)=(source_cursor IS NULL)), CHECK((source_cursor_kind IS NULL)=(source_cursor IS NULL)), CHECK((projection_cursor_channel IS NULL)=(projection_cursor IS NULL)),
 channel_hashes jsonb NOT NULL DEFAULT jsonb_build_object('agent',repeat('0',64),'mdm',repeat('0',64)),
 agent_revision bigint NOT NULL DEFAULT 0 CHECK(agent_revision>=0),mdm_revision bigint NOT NULL DEFAULT 0 CHECK(mdm_revision>=0),
 PRIMARY KEY(tenant_id,id)
);
ALTER TABLE "###, $schema, r###"scope_projection_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $schema, r###"scope_projection_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $schema, r###"scope_projection_runs USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $schema, "scope_projection_runs TO ", $scope_runtime, r###";
GRANT UPDATE(phase,source_cursor_source,source_cursor_kind,source_cursor,projection_cursor_channel,projection_cursor,channel_hashes,agent_revision,mdm_revision) ON "###, $schema, "scope_projection_runs TO ", $scope_runtime, r###";
GRANT SELECT ON "###, $schema, "scope_projection_runs TO ", $command_runtime, ",", $access, r###";
CREATE TABLE "###, $schema, r###"scope_channel_results (
 tenant_id uuid NOT NULL,
 run uuid NOT NULL,
 channel text NOT NULL CHECK(channel IN('agent','mdm')),
 device uuid NOT NULL,
 matched boolean NOT NULL,
 pending boolean NOT NULL,
 target jsonb NOT NULL CHECK(octet_length(target::text)<=1024),
 entry_revision bigint NOT NULL CHECK(entry_revision>=0),
 PRIMARY KEY(tenant_id,run,channel,device)
);

ALTER TABLE "###, $schema, r###"scope_channel_results ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $schema, r###"scope_channel_results FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $schema, r###"scope_channel_results USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

"###, $index_44, " ON ", $schema, r###"scope_channel_results(tenant_id,run,channel,device);

CREATE FUNCTION "###, $schema, r###"guard_scope_channel_result() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p text;
BEGIN
 SELECT phase INTO STRICT p FROM "###, $schema, r###"scope_projection_runs WHERE tenant_id=NEW.tenant_id AND id=NEW.run;
 IF p NOT IN('sources','project') THEN RAISE EXCEPTION 'scope channel result is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;$$;

REVOKE ALL ON FUNCTION "###, $schema, r###"guard_scope_channel_result() FROM PUBLIC;

CREATE TRIGGER scope_channel_result_guard BEFORE INSERT OR UPDATE ON "###, $schema, "scope_channel_results FOR EACH ROW EXECUTE FUNCTION ", $schema, r###"guard_scope_channel_result();

"###, $channel_admission_header, r###"p_scope uuid,p_channel text,p_device uuid) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE tenant uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 status jsonb; current_run uuid; frozen jsonb; evaluation record; published record;
BEGIN
 IF p_channel NOT IN('agent','mdm') THEN RAISE EXCEPTION 'invalid scope channel' USING ERRCODE='23514'; END IF;
 status="###, $schema, r###"scope_state(p_scope,NULL);
 IF status->>'state'<>'fresh' THEN RETURN status; END IF;
 SELECT s.resolution,r.input INTO current_run,frozen FROM "###, $schema, r###"scopes s
 JOIN "###, $schema, r###"scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution)
 WHERE s.tenant_id=tenant AND s.id=p_scope AND NOT s.deleted;
 IF NOT FOUND THEN RAISE EXCEPTION 'scope resolution unavailable' USING ERRCODE='23514'; END IF;
 -- The ordinal source identity is the immutable Scope input's identity, never a current group expansion.
 WITH evidence AS MATERIALIZED (
  SELECT m.source,m.unknown,m.input FROM "###, $schema, r###"scope_source_members m
  WHERE m.tenant_id=tenant AND m.run=current_run
   AND m.input->'members' @> jsonb_build_array(jsonb_build_object('device',p_device,'channel',p_channel))
  ORDER BY m.source,m.object_kind,m.object_id LIMIT 16001
 ), evidence_state AS MATERIALIZED (
  SELECT e.source,CASE WHEN e.unknown OR e.input->>'verified' IS DISTINCT FROM 'true' THEN false
   ELSE "###, $object_qualification, r###" IS NOT NULL END AS valid FROM evidence e
 ), memberships AS (
  SELECT src.value->'reference' AS reference,
   EXISTS(SELECT FROM evidence_state e WHERE e.source=src.ordinal-1 AND e.valid) AS known,
   EXISTS(SELECT FROM evidence_state e WHERE e.source=src.ordinal-1 AND NOT e.valid) AS uncertain
  FROM jsonb_array_elements(frozen->'sources') WITH ORDINALITY src(value,ordinal)
 ), selected AS (
  SELECT *,coalesce(frozen#>'{definition,targets}' @> jsonb_build_array(reference),false) AS target,
   coalesce(frozen#>'{definition,limitations}' @> jsonb_build_array(reference),false) AS limitation,
   coalesce(frozen#>'{definition,exclusions}' @> jsonb_build_array(reference),false) AS exclusion
  FROM memberships
 )
 SELECT (SELECT count(*) FROM evidence)>16000 AS overflow,
  coalesce(bool_or(target AND known),false) AS target_known,
  coalesce(bool_or(target AND NOT known AND uncertain),false) AS target_unknown,
  coalesce(bool_or(limitation AND known),false) AS limit_known,
  coalesce(bool_or(limitation AND NOT known AND uncertain),false) AS limit_unknown,
  coalesce(bool_or(exclusion AND known),false) AS exclude_known,
  coalesce(bool_or(exclusion AND NOT known AND uncertain),false) AS exclude_unknown
 INTO evaluation FROM selected;
 IF evaluation.overflow THEN
  RAISE EXCEPTION 'invalid scope source evidence' USING ERRCODE='23514';
 END IF;
 IF NOT evaluation.target_known AND NOT evaluation.target_unknown THEN
  RETURN jsonb_build_object('state','excluded');
 END IF;
 IF evaluation.exclude_known THEN RETURN jsonb_build_object('state','excluded'); END IF;
 -- A known exclusion wins; genuinely unknown candidates still wait.
 IF NOT evaluation.target_known
  OR (frozen#>'{definition,limitations}' IS NOT NULL AND frozen#>'{definition,limitations}'<>'null'::jsonb
   AND NOT evaluation.limit_known AND evaluation.limit_unknown)
  OR (NOT evaluation.exclude_known AND evaluation.exclude_unknown) THEN
  RETURN jsonb_build_object('state','pending');
 END IF;
 IF evaluation.exclude_known OR (frozen#>'{definition,limitations}' IS NOT NULL
  AND frozen#>'{definition,limitations}'<>'null'::jsonb AND NOT evaluation.limit_known) THEN
  RETURN jsonb_build_object('state','excluded');
 END IF;
 -- A source-algebra match still needs the exact published per-channel admission.
 SELECT matched,pending,entry_revision INTO published FROM "###, $schema, r###"scope_channel_results
 WHERE tenant_id=tenant AND run=current_run AND channel=p_channel AND device=p_device;
 IF FOUND AND published.pending THEN RETURN jsonb_build_object('state','pending'); END IF;
 IF FOUND AND published.matched AND NOT published.pending AND published.entry_revision>0 THEN
  RETURN jsonb_build_object('state','eligible','entry',published.entry_revision);
 END IF;
 RETURN jsonb_build_object('state','excluded');
END $$;

REVOKE ALL ON FUNCTION "###, $schema, r###"channel_admission(uuid,text,uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION "###, $schema, "channel_admission(uuid,text,uuid) TO ", $access, ",", $inventory_runtime, ",", $scope_runtime, ",", $policy_runtime, ",", $telemetry_runtime, ",", $command_runtime, r###";
COMMIT;
"###),
                projection_relations: concat!(r###"BEGIN;
-- Native Agent registration rechecks only the frozen source read authority.

ALTER TABLE "###, $schema, "scope_channel_results ADD FOREIGN KEY(tenant_id,run) REFERENCES ", $schema, r###"scope_runs(tenant_id,id);

GRANT SELECT,INSERT ON "###, $schema, "scope_channel_results TO ", $scope_runtime, r###";

GRANT SELECT ON "###, $schema, "scope_channel_results TO ", $command_runtime, r###";

GRANT UPDATE(matched,pending,target,entry_revision) ON "###, $schema, "scope_channel_results TO ", $scope_runtime, r###";
COMMIT;
GRANT SELECT ON "###, $schema, "scope_channel_results TO ", $access, r###";

ALTER TABLE "###, $schema, "scope_projection_runs ADD FOREIGN KEY(tenant_id,id) REFERENCES ", $schema, r###"scope_runs(tenant_id,id);

GRANT SELECT ON "###, $schema, "scope_projection_runs, ", $schema, "scope_channel_results TO ", $policy_runtime, r###";
"###),
                projection_admission: concat!(r###"WITH execution_roles AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')
), reachable AS (
 SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT 1 FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))
), expected(name,updates,keys) AS (VALUES
 ('scope_projection_runs',ARRAY['phase','source_cursor','projection_cursor','channel_hashes','agent_revision','mdm_revision']::text[],ARRAY['tenant_id','id']::text[]),
 ('scope_channel_results',ARRAY['matched','pending','target','entry_revision']::text[],ARRAY['tenant_id','run','channel','device']::text[])
), relations AS (
 SELECT e.*,c.oid,c.relowner,c.relrowsecurity,c.relforcerowsecurity,c.relacl FROM expected e
 JOIN pg_class c ON c.oid=to_regclass('"###, $schema, r###"'||e.name) AND c.relkind='r'
)
SELECT (SELECT count(*) FROM relations)=2
AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR oid IN(SELECT relowner FROM relations))
AND NOT EXISTS(SELECT 1 FROM relations t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR has_table_privilege(current_user,t.oid,'INSERT')<>$1
 OR has_table_privilege(current_user,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
    AND (has_column_privilege(current_user,t.oid,a.attnum,'UPDATE')<>($1 AND a.attname=ANY(t.updates)) OR has_column_privilege(current_user,t.oid,a.attnum,'REFERENCES')))
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=t.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
  AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
  AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 OR NOT EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=t.oid AND k.contype='p' AND k.convalidated AND NOT k.condeferrable
   AND (SELECT array_agg(a.attname::text ORDER BY key.n) FROM unnest(k.conkey) WITH ORDINALITY key(attnum,n) JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=key.attnum)=t.keys)
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable)))
AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM relations) AND NOT tgisinternal AND NOT(
 (tgname='scope_channel_result_guard' AND tgrelid='"###, $schema, "scope_channel_results'::regclass AND tgfoid='", $schema, r###"guard_scope_channel_result()'::regprocedure AND tgenabled='O')))
AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='"###, $schema, r###"scope_channel_results'::regclass AND tgname='scope_channel_result_guard' AND tgenabled='O')
AND NOT EXISTS(SELECT 1 FROM relations t CROSS JOIN reachable r WHERE
 has_table_privilege(r.oid,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
  AND (has_column_privilege(r.oid,t.oid,a.attnum,'REFERENCES')
   OR (has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE') AND NOT ($1 AND a.attname=ANY(t.updates))))))
AND NOT EXISTS(SELECT 1 FROM relations t JOIN pg_attribute col ON col.attrelid=t.oid
 CROSS JOIN LATERAL aclexplode(col.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
"###),
                group_blocker_facts: concat!(r#"
SELECT s.id,s.revision,s.policy_id,s.stage_id,
 ARRAY(SELECT role FROM (VALUES ('target',v.definition->'targets'),('limitation',v.definition->'limitations'),('exclusion',v.definition->'exclusions')) roles(role,entries)
 WHERE EXISTS(SELECT FROM jsonb_array_elements(coalesce(nullif(entries,'null'::jsonb),'[]'::jsonb)) e WHERE e->>'kind'='group' AND (e->>'id')::uuid=$2::uuid)) AS roles
FROM "#, $schema, "scope_sources e JOIN ", $schema, "scopes s ON(s.tenant_id,s.id)=(e.tenant_id,e.scope) JOIN ", $schema, r#"scope_versions v ON(v.tenant_id,v.id,v.revision)=(s.tenant_id,s.id,s.revision)
WHERE e.tenant_id=$1::uuid AND e.kind='group' AND e.target=$2::uuid::text AND NOT s.deleted
"#),
                group_reference_facts: concat!(r###"
SELECT s.tenant_id,s.id,s.policy_id,s.stage_id,s.revision,s.deleted,s.resolution,s.resolution_revision,s.calculation_revision,
 r.phase,
 ARRAY(SELECT (e->>'id')::uuid FROM jsonb_array_elements(coalesce(nullif(v.definition->'targets','null'::jsonb),'[]'::jsonb)) e WHERE e->>'kind'='group' ORDER BY (e->>'id')::uuid) AS target_group_ids,
 ARRAY(SELECT (e->>'id')::uuid FROM jsonb_array_elements(coalesce(nullif(v.definition->'limitations','null'::jsonb),'[]'::jsonb)) e WHERE e->>'kind'='group' ORDER BY (e->>'id')::uuid) AS limitation_group_ids,
 ARRAY(SELECT (e->>'id')::uuid FROM jsonb_array_elements(coalesce(nullif(v.definition->'exclusions','null'::jsonb),'[]'::jsonb)) e WHERE e->>'kind'='group' ORDER BY (e->>'id')::uuid) AS exclusion_group_ids,
 ARRAY(SELECT e.target::uuid FROM "###, $schema, r###"scope_sources e WHERE e.tenant_id=s.tenant_id AND e.scope=s.id AND e.kind='group' ORDER BY e.target)::uuid[] AS group_ids
FROM "###, $schema, r###"scopes s
JOIN "###, $schema, r###"scope_versions v ON(v.tenant_id,v.id,v.revision)=(s.tenant_id,s.id,s.revision)
LEFT JOIN "###, $schema, r###"scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution)
WHERE s.tenant_id=$1::uuid
"###),
                admission: concat!(r###"WITH execution_roles AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')
), reachable AS (
 SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT 1 FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))
), owned AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname="###, $schema_name, " AND c.relkind='r' AND c.relname IN(", $asset_dispatch_name, ",'scope_results','scope_runs','scope_source_members','scope_sources','scope_versions','scopes',", $tasks_name, ",", $operations_name, r###")
)
SELECT current_setting('transaction_isolation')='read committed'
AND (SELECT count(*) FROM owned)=9
AND NOT EXISTS(SELECT 1 FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR oid IN(SELECT relowner FROM owned))
AND NOT EXISTS(SELECT 1 FROM owned t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR NOT has_table_privilege(current_user,t.oid,'SELECT') OR has_table_privilege(current_user,t.oid,'INSERT')<>(t.relname NOT IN('scopes','scope_versions','scope_sources',"###, $operations_name, r###"))
 OR has_table_privilege(current_user,t.oid,'TRUNCATE') OR has_table_privilege(current_user,t.oid,'TRIGGER')
 OR has_table_privilege(current_user,t.oid,'REFERENCES')
 OR has_table_privilege(current_user,t.oid,'DELETE')
 OR (SELECT count(*) FROM pg_policy p WHERE p.polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=t.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polroles=ARRAY[0::oid]
  AND p.polpermissive
  AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
  AND pg_get_expr(p.polwithcheck,p.polrelid)=pg_get_expr(p.polqual,p.polrelid)))
AND NOT EXISTS(SELECT 1 FROM owned t JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
 WHERE has_column_privilege(current_user,t.oid,a.attnum,'UPDATE') <>
 ((t.relname='scopes' AND a.attname IN('resolution','resolution_revision','calculation_revision','input_revision','input_epoch','input_xid'))
 OR (t.relname='scope_runs' AND a.attname IN('phase','source_index','source_cursor_kind','source_cursor','evaluation_cursor_kind','evaluation_cursor','object_count','member_count'))
 OR (t.relname="###, $tasks_name, r###" AND a.attname IN('completed','failure','failure_detail','replacement_task'))
 OR (t.relname="###, $asset_dispatch_name, r###" AND a.attname IN('input_failed','from_cut','to_cut','event_after','page_through','cursor','relation_consumed','relation_watermark','relation_position','relation_cursor'))))
AND has_function_privilege(current_user,'"###, $schema, r###"scope_admission(uuid,uuid)','EXECUTE')
AND has_function_privilege(current_user,'"###, $schema, r###"scope_state(uuid,uuid)','EXECUTE')

AND NOT EXISTS(SELECT 1 FROM owned t WHERE NOT EXISTS(
 SELECT 1 FROM pg_constraint k WHERE k.conrelid=t.oid AND k.contype='p' AND k.convalidated AND NOT k.condeferrable
 AND (SELECT array_agg(a.attname::text ORDER BY key.n) FROM unnest(k.conkey) WITH ORDINALITY key(attnum,n) JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=key.attnum)=
 CASE t.relname WHEN "###, $operations_name, " THEN ARRAY['tenant_id','actor','id'] WHEN 'scope_results' THEN ARRAY['tenant_id','run','object_kind','object_id'] WHEN 'scope_source_members' THEN ARRAY['tenant_id','run','source','object_kind','object_id'] WHEN 'scope_sources' THEN ARRAY['tenant_id','scope','kind','target'] WHEN 'scope_versions' THEN ARRAY['tenant_id','id','revision'] WHEN ", $asset_dispatch_name, r###" THEN ARRAY['tenant_id'] ELSE ARRAY['tenant_id','id'] END))
AND NOT EXISTS(SELECT 1 FROM owned t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM owned) AND NOT tgisinternal)
-- Required rights are checked on current_user above. Every role reachable by the
-- original login must also remain within the write capability, even without INHERIT.
AND NOT EXISTS(SELECT 1 FROM owned t CROSS JOIN reachable r WHERE
 has_table_privilege(r.oid,t.oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_table_privilege(r.oid,t.oid,'DELETE')
 OR (has_any_column_privilege(r.oid,t.oid,'INSERT') AND t.relname IN('scopes','scope_versions','scope_sources',"###, $operations_name, r###"))
 OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
  AND (has_column_privilege(r.oid,t.oid,a.attnum,'REFERENCES')
   OR (has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE') AND NOT (
    (t.relname='scopes' AND a.attname IN('resolution','resolution_revision','calculation_revision','input_revision','input_epoch','input_xid'))
    OR (t.relname='scope_runs' AND a.attname IN('phase','source_index','source_cursor_kind','source_cursor','evaluation_cursor_kind','evaluation_cursor','object_count','member_count'))
    OR (t.relname="###, $tasks_name, r###" AND a.attname IN('completed','failure','failure_detail','replacement_task'))
    OR (t.relname="###, $asset_dispatch_name, r###" AND a.attname IN('input_failed','from_cut','to_cut','event_after','page_through','cursor','relation_consumed','relation_watermark','relation_position','relation_cursor')))))))
AND NOT EXISTS(SELECT 1 FROM owned t JOIN pg_attribute col ON col.attrelid=t.oid
 CROSS JOIN LATERAL aclexplode(col.attacl) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
"###),
                configuration_admission: concat!(r###"WITH execution_roles AS (
 SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')
), reachable AS (
 SELECT r.* FROM pg_roles r WHERE EXISTS(SELECT FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE'))
), expected(relation,selectable,insertable,deletable,updates) AS (VALUES
 ('"###, $schema, r###"scopes',true,true,false,ARRAY['revision','deleted','input_revision','input_epoch','input_xid']),
 ('"###, $schema, r###"scope_versions',true,true,false,ARRAY[]::text[]),
 ('"###, $schema, r###"scope_sources',true,true,true,ARRAY[]::text[]),
 ('"###, $schema, r###"scope_runs',true,false,false,ARRAY['phase']),
 ('"###, $schema, r###"scope_results',true,false,false,ARRAY[]::text[]),
 ('"###, $schema, r###"scope_source_members',true,false,false,ARRAY[]::text[]),
 ('"###, $schema, r###"scope_projection_runs',true,false,false,ARRAY[]::text[]),
 ('"###, $schema, r###"scope_channel_results',true,false,false,ARRAY[]::text[]),
 ('"###, $asset_dispatch, r###"',false,false,false,ARRAY[]::text[]),
 ('"###, $group_changes, r###"',false,false,false,ARRAY[]::text[]),
 ('"###, $tasks, r###"',true,true,false,ARRAY['completed','failure','failure_detail','replacement_task']),
 ('"###, $operations, r###"',true,true,false,ARRAY[]::text[])
), owned AS (SELECT e.*,c.* FROM expected e JOIN pg_class c ON c.oid=to_regclass(e.relation))
SELECT current_setting('transaction_isolation')='read committed'
AND (SELECT count(*) FROM owned)=12
AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR oid IN(SELECT relowner FROM owned)
 OR has_schema_privilege(oid,"###, $schema_name, r###",'CREATE'))
AND NOT EXISTS(SELECT FROM owned t WHERE NOT relrowsecurity OR NOT relforcerowsecurity
 OR has_table_privilege(current_user,t.oid,'SELECT')<>selectable
 OR has_table_privilege(current_user,t.oid,'INSERT')<>insertable
 OR has_table_privilege(current_user,t.oid,'DELETE')<>deletable
 OR (SELECT count(*) FROM pg_policy WHERE polrelid=t.oid)<>1
 OR NOT EXISTS(SELECT FROM pg_policy p WHERE p.polrelid=t.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polroles=ARRAY[0::oid] AND p.polpermissive
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polwithcheck,p.polrelid)=pg_get_expr(p.polqual,p.polrelid))
 OR EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
 AND has_column_privilege(current_user,t.oid,a.attnum,'UPDATE')<>(a.attname::text=ANY(t.updates))))
AND NOT EXISTS(SELECT FROM owned t CROSS JOIN reachable r WHERE has_table_privilege(r.oid,t.oid,'UPDATE,TRUNCATE,TRIGGER,REFERENCES')
 OR (has_table_privilege(r.oid,t.oid,'INSERT') AND NOT t.insertable) OR (has_table_privilege(r.oid,t.oid,'DELETE') AND NOT t.deletable)
 OR EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
 AND (has_column_privilege(r.oid,t.oid,a.attnum,'REFERENCES')
 OR (has_column_privilege(r.oid,t.oid,a.attnum,'INSERT') AND NOT t.insertable)
 OR (has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE') AND NOT a.attname::text=ANY(t.updates)))))
AND NOT EXISTS(SELECT FROM owned t,LATERAL aclexplode(coalesce(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
AND NOT EXISTS(SELECT FROM owned t JOIN pg_attribute col ON col.attrelid=t.oid CROSS JOIN LATERAL aclexplode(col.attacl) a
 WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
AND EXISTS(SELECT FROM pg_index i WHERE i.indrelid='"###, $schema, r###"scopes'::regclass AND i.indisunique AND i.indnullsnotdistinct AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL
 AND (SELECT array_agg(a.attname::text ORDER BY k.n) FROM unnest(i.indkey) WITH ORDINALITY k(num,n) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.num WHERE k.n<=i.indnkeyatts)=ARRAY['tenant_id','policy_id','stage_id'])
"###),
                access_admission: concat!(r###"WITH expected(name) AS (VALUES
 ('"###, $schema, r###"scopes'),
 ('"###, $schema, r###"scope_runs'),
 ('"###, $schema, r###"scope_source_members')
), relations AS (
 SELECT c.* FROM expected e JOIN pg_class c ON c.oid=to_regclass(e.name)
)
SELECT (SELECT count(*) FROM relations)=(SELECT count(*) FROM expected)
 AND NOT EXISTS(SELECT 1 FROM relations c WHERE c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
  OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
  OR NOT has_table_privilege(current_user,c.oid,'SELECT')
  OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES'))
 AND NOT EXISTS(SELECT 1 FROM relations c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM relations c JOIN pg_attribute col ON col.attrelid=c.oid,LATERAL aclexplode(col.attacl) a
  WHERE a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND a.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM relations c WHERE
 (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant'
 AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
 AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
 AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid)))
"###),
                authority_admission: concat!(r###"-- Privileged kernels: exact bodies come from the corresponding owner's installation SQL.
WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES
 ('"###, $schema, "scope_admission(uuid,uuid)', 'plpgsql', 'jsonb', true, false, 'v', ARRAY['p_scope','p_device']::text[], ARRAY['search_path=pg_catalog']::text[], $1::text, ARRAY['", $access, "','", $command_runtime, "','", $scope_runtime, "','", $policy_runtime, "','", $inventory_runtime, "','", $telemetry_runtime, "','", $role_mdm_identity_runtime, "','", $owner, r###"']::text[]),
 ('"###, $schema, "scope_state(uuid,uuid)', 'plpgsql', 'jsonb', true, false, 's', ARRAY['p_scope','p_device']::text[], ARRAY['search_path=pg_catalog']::text[], $2::text, ARRAY['", $access, "','", $command_runtime, "','", $scope_runtime, "','", $policy_runtime, "','", $inventory_runtime, "','", $telemetry_runtime, "','", $role_mdm_identity_runtime, "','", $owner, r###"']::text[]),
 ('"###, $schema, "channel_admission(uuid,text,uuid)', 'plpgsql', 'jsonb', true, false, 's', ARRAY['p_scope','p_channel','p_device']::text[], ARRAY['search_path=pg_catalog']::text[], $3::text, ARRAY['", $access, "','", $command_runtime, "','", $inventory_runtime, "','", $scope_runtime, "','", $policy_runtime, "','", $telemetry_runtime, "','", $role_mdm_identity_runtime, "','", $owner, r###"']::text[])
)
SELECT e.signature FROM expected e
LEFT JOIN pg_proc p ON p.oid=to_regprocedure(e.signature)
LEFT JOIN pg_language l ON l.oid=p.prolang
LEFT JOIN pg_roles r ON r.oid=p.proowner
WHERE p.oid IS NULL OR l.lanname<>e.language OR p.prorettype<>to_regtype(e.result)
 OR p.prokind<>'f' OR p.prosecdef<>e.definer OR p.proretset<>e.returns_set
 OR p.provolatile::text<>e.volatility OR p.proleakproof OR p.prosrc<>e.body
 OR coalesce(p.proargnames,ARRAY[]::text[]) IS DISTINCT FROM e.names OR p.proconfig IS DISTINCT FROM e.config
 OR r.rolname<>'"###, $owner, r###"' OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
 OR pg_has_role(current_user,r.oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM (VALUES('"###, $schema, "scopes'),('", $schema, r###"scope_versions')) required(relation)
 LEFT JOIN pg_class c ON c.oid=to_regclass(required.relation)
 WHERE c.oid IS NULL OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner<>p.proowner)
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
 WHERE a.grantee=0 OR (a.grantee<>p.proowner AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT pg_get_userbyid(a.grantee)=ANY(e.roles))))
ORDER BY e.signature LIMIT 1
"###),
                lib_accept_group_change_in_1: concat!("INSERT INTO ", $group_changes, "(tenant_id,event_id,group_id) VALUES($1::uuid,$2,$3)"),
                lib_group_change_page_in_1: concat!("SELECT event_id,group_id,cursor FROM ", $group_changes, " WHERE tenant_id=$1::uuid AND NOT completed ORDER BY event_id LIMIT 1 FOR UPDATE SKIP LOCKED"),
                lib_group_change_page_in_2: concat!("SELECT DISTINCT s.id FROM ", $schema, "scopes s JOIN ", $schema, "scope_sources e ON(e.tenant_id,e.scope)=(s.tenant_id,s.id) WHERE s.tenant_id=$1::uuid AND NOT s.deleted AND e.kind='group' AND e.target=$2 AND ($3::uuid IS NULL OR s.id>$3) ORDER BY s.id LIMIT 65"),
                lib_complete_group_change_page_in_1: concat!("UPDATE ", $group_changes, " SET cursor=$3,completed=$4 WHERE tenant_id=$1::uuid AND event_id=$2 AND NOT completed"),
                lib_target_members_in_1: concat!("SELECT DISTINCT m.object_kind,m.object_id FROM ", $schema, "scopes s JOIN ", $schema, "scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution) JOIN ", $schema, "scope_source_members m ON(m.tenant_id,m.run)=(r.tenant_id,r.id) JOIN LATERAL jsonb_array_elements(r.input->'sources') WITH ORDINALITY source(value,ordinal) ON source.ordinal=m.source+1 WHERE s.tenant_id=$1::uuid AND s.id=$2 AND r.input->'definition'->'targets' @> jsonb_build_array(source.value->'reference') AND EXISTS(SELECT 1 FROM unnest($3::smallint[],$4::uuid[]) candidate(kind,id) WHERE (candidate.kind,candidate.id)=(m.object_kind,m.object_id))"),
                store_head_in_1: concat!("SELECT s.revision,s.resolution,s.resolution_revision,s.calculation_revision,v.definition FROM ", $schema, "scopes s JOIN ", $schema, "scope_versions v USING(tenant_id,id,revision) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted FOR UPDATE OF s"),
                store_head_in_2: concat!("SELECT s.revision,s.resolution,s.resolution_revision,s.calculation_revision,v.definition FROM ", $schema, "scopes s JOIN ", $schema, "scope_versions v USING(tenant_id,id,revision) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted FOR SHARE OF s"),
                store_put_in_1: concat!("INSERT INTO ", $schema, "scopes(tenant_id,id,revision,deleted,policy_id,stage_id) VALUES($1::uuid,$2,1,false,$3,$4) ON CONFLICT DO NOTHING"),
                store_put_in_2: concat!("UPDATE ", $schema, "scopes SET revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2 AND revision=$3 AND NOT deleted AND policy_id=$4 AND stage_id IS NOT DISTINCT FROM $5"),
                store_put_in_3: concat!("INSERT INTO ", $schema, "scope_versions(tenant_id,id,revision,definition) VALUES($1::uuid,$2,$3,$4)"),
                store_retire_in: concat!("UPDATE ", $schema, "scopes SET deleted=true WHERE tenant_id=$1::uuid AND id=$2 AND revision=$3 AND NOT deleted AND policy_id=$4 AND stage_id IS NOT DISTINCT FROM $5"),
                store_owned_in: concat!("SELECT s.id,s.deleted,s.revision,s.resolution,s.resolution_revision,s.calculation_revision,v.definition FROM ", $schema, "scopes s JOIN ", $schema, "scope_versions v USING(tenant_id,id,revision) WHERE s.tenant_id=$1::uuid AND s.policy_id=$2 AND s.stage_id IS NOT DISTINCT FROM $3 FOR SHARE OF s"),
                store_owner_in: concat!("SELECT policy_id,stage_id FROM ", $schema, "scopes WHERE tenant_id=$1::uuid AND id=$2"),
                store_replace_sources_in_1: concat!("DELETE FROM ", $schema, "scope_sources WHERE tenant_id=$1::uuid AND scope=$2"),
                store_replace_sources_in_2: concat!("INSERT INTO ", $schema, "scope_sources SELECT $1::uuid,$2,* FROM unnest($3::text[],$4::uuid[])"),
                store_create_run_in_1: concat!("INSERT INTO ", $schema, "scope_runs(tenant_id,id,scope,definition_revision,asset_cut,input,fingerprint,phase,covered_inputs) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,'sources',$8)"),
                store_run_in_1: concat!("SELECT * FROM ", $schema, "scope_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                store_stage_sources_in_1: concat!("INSERT INTO ", $schema, "scope_source_members(tenant_id,run,source,object_kind,object_id,unknown,input) SELECT $1::uuid,$2,$3,k,d,u,i FROM unnest($4::smallint[],$5::uuid[],$6::boolean[],$7::jsonb[]) AS p(k,d,u,i)"),
                store_stage_sources_in_2: concat!("UPDATE ", $schema, "scope_runs SET source_index=$3,source_cursor_kind=$4,source_cursor=$5 WHERE tenant_id=$1::uuid AND id=$2"),
                store_phase_in_1: concat!("UPDATE ", $schema, "scope_runs SET phase=$3 WHERE tenant_id=$1::uuid AND id=$2"),
                store_publish_in_1: concat!("WITH old AS (SELECT object_kind,object_id,matched,explanation->'reasons' AS reasons,explanation->'identityRevision' AS identity FROM ", $schema, "scope_results WHERE tenant_id=$1::uuid AND run=$2), new AS (SELECT object_kind,object_id,matched,explanation->'reasons' AS reasons,explanation->'identityRevision' AS identity FROM ", $schema, "scope_results WHERE tenant_id=$1::uuid AND run=$3) SELECT EXISTS((SELECT * FROM old EXCEPT SELECT * FROM new) UNION ALL (SELECT * FROM new EXCEPT SELECT * FROM old))"),
                store_publish_in_2: concat!("UPDATE ", $schema, "scope_runs SET phase='published' WHERE tenant_id=$1::uuid AND id=$2 AND phase='ready'"),
                store_publish_in_3: concat!("UPDATE ", $schema, "scopes SET resolution=$3,resolution_revision=$4,calculation_revision=calculation_revision+1 WHERE tenant_id=$1::uuid AND id=$2"),
                store_definition_at_1: concat!("SELECT definition FROM ", $schema, "scope_versions WHERE tenant_id=$1::uuid AND id=$2 AND revision=$3"),
                store_enqueue_in_1: concat!("SELECT id FROM ", $tasks, " WHERE tenant_id=$1::uuid AND scope=$2 AND NOT completed"),
                store_enqueue_in_2: concat!("INSERT INTO ", $tasks, "(tenant_id,id,scope) VALUES($1::uuid,$2,$3)"),
                store_request_inputs: concat!("UPDATE ", $schema, "scopes SET input_revision=input_revision+1,input_epoch=(SELECT id FROM mdm.asset_epochs WHERE active),input_xid=pg_current_xact_id() WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted"),
                store_covered_inputs: concat!("SELECT CASE WHEN input_revision=0 OR mdm.asset_cut_contains($3,input_epoch,input_xid) THEN input_revision ELSE 0 END FROM ", $schema, "scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted"),
                store_uncovered_inputs: concat!("SELECT input_revision>$3 FROM ", $schema, "scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted"),
                store_task_in_1: concat!("SELECT t.*,EXISTS(SELECT 1 FROM ", $schema, "scope_runs r WHERE r.tenant_id=t.tenant_id AND r.id=t.id) AS forwarded FROM ", $tasks, " t WHERE tenant_id=$1::uuid AND id=$2"),
                store_finish_task_in_1: concat!("UPDATE ", $tasks, " SET completed=true,failure=$3 WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed"),
                store_replace_task_in_1: concat!("UPDATE ", $tasks, " SET replacement_task=$3 WHERE tenant_id=$1::uuid AND id=$2"),
                store_evaluate_page_in_1: concat!("SELECT DISTINCT object_kind,object_id FROM ", $schema, r###"scope_source_members WHERE tenant_id=$1::uuid AND run=$2 AND source=ANY($3) AND ($4::smallint IS NULL OR (object_kind,object_id)>($4,$5::uuid)) ORDER BY object_kind,object_id LIMIT $6"###),
                store_evaluate_page_in_2: concat!("INSERT INTO ", $schema, "scope_results(tenant_id,run,object_kind,object_id,matched,explanation) SELECT $1::uuid,$2,k,d,m,e FROM unnest($3::smallint[],$4::uuid[],$5::boolean[],$6::jsonb[]) AS p(k,d,m,e)"),
                store_evaluate_page_in_3: concat!("UPDATE ", $schema, "scope_runs SET object_count=object_count+$3,member_count=member_count+$3,evaluation_cursor_kind=$4,evaluation_cursor=$5,phase=$6 WHERE tenant_id=$1::uuid AND id=$2"),
                store_asset_page_in_1: concat!("INSERT INTO ", $asset_dispatch, "(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING"),
                store_asset_page_in_2: concat!("SELECT from_cut,to_cut,event_after,page_through,cursor FROM ", $asset_dispatch, " WHERE tenant_id=$1::uuid FOR UPDATE"),
                store_asset_page_in_3: concat!("UPDATE ", $asset_dispatch, " SET from_cut=$2,to_cut=NULL,event_after=0,page_through=NULL,cursor=NULL WHERE tenant_id=$1::uuid"),
                store_asset_page_in_4: concat!("UPDATE ", $asset_dispatch, " SET to_cut=$2,page_through=$3 WHERE tenant_id=$1::uuid"),
                store_asset_page_in_5: concat!("WITH from_cut AS MATERIALIZED(SELECT * FROM mdm.asset_cut_context($2)),to_cut AS MATERIALIZED(SELECT * FROM mdm.asset_cut_context($3)),changed AS (SELECT DISTINCT a.identity ->> 'device' AS device FROM mdm.asset_changes AS a WHERE a.tenant_id = CAST($1 AS uuid) AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,a.source_epoch,a.writer_xid) FROM from_cut),false) AND coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,a.source_epoch,a.writer_xid) FROM to_cut),false) AND a.revision > $4 AND a.revision <= $5 AND (a.kind IN ('device', 'source', 'credential') OR 'channel.agent.installation' = ANY(a.fields))) SELECT DISTINCT s.scope FROM changed INNER JOIN ", $schema, "scope_sources AS s ON s.tenant_id = CAST($1 AS uuid) AND s.kind = 'device' AND s.target = changed.device::uuid INNER JOIN ", $schema, "scopes AS h ON (h.tenant_id, h.id) = (s.tenant_id, s.scope) WHERE NOT h.deleted AND (CAST($6 AS uuid) IS NULL OR s.scope > $6) ORDER BY s.scope LIMIT 33"),
                store_complete_asset_page_in_1: concat!("UPDATE ", $asset_dispatch, " SET event_after=$2,page_through=$3,cursor=$4 WHERE tenant_id=$1::uuid AND to_cut=$5"),
                store_input_failed: concat!("SELECT coalesce((SELECT input_failed FROM ", $asset_dispatch, " WHERE tenant_id=$1::uuid),false)"),
                store_set_input_failed: concat!("INSERT INTO ", $asset_dispatch, "(tenant_id,input_failed) VALUES($1::uuid,$2) ON CONFLICT(tenant_id) DO UPDATE SET input_failed=excluded.input_failed"),
                store_inputs_pending_in_1: concat!("WITH input_cut AS MATERIALIZED(SELECT * FROM mdm.asset_cut_context((SELECT from_cut FROM ", $asset_dispatch, " WHERE tenant_id=$1::uuid))) SELECT EXISTS(SELECT FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,source_epoch,writer_xid) FROM input_cut),false)) OR $2>coalesce((SELECT relation_consumed FROM ", $asset_dispatch, " WHERE tenant_id=$1::uuid),0) OR EXISTS(SELECT 1 FROM ", $group_changes, " WHERE tenant_id=$1::uuid AND NOT completed)"),
                store_relation_window_in_1: concat!("INSERT INTO ", $asset_dispatch, "(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING"),
                store_relation_window_in_2: concat!("SELECT relation_consumed,relation_watermark,relation_position,relation_cursor FROM ", $asset_dispatch, " WHERE tenant_id=$1::uuid FOR UPDATE"),
                store_relation_targets_in_1: concat!("SELECT DISTINCT s.scope FROM ", $schema, "scope_sources s JOIN ", $schema, "scopes h ON(h.tenant_id,h.id)=(s.tenant_id,s.scope) WHERE s.tenant_id=$1::uuid AND s.kind='device' AND s.target=ANY($2) AND NOT h.deleted AND ($3::uuid IS NULL OR s.scope>$3) ORDER BY s.scope LIMIT 33"),
                store_complete_relation_page_in_1: concat!("UPDATE ", $asset_dispatch, " SET relation_consumed=$2,relation_watermark=$3,relation_position=$4,relation_cursor=$5 WHERE tenant_id=$1::uuid"),
                state_admission_on_1: concat!("SELECT ", $schema, "scope_admission($2,NULL) WHERE nullif(current_setting('rss.tenant_id',true),'')::uuid=$1::uuid"),
                state_state_on_1: concat!("SELECT ", $schema, "scope_state($2,NULL) WHERE nullif(current_setting('rss.tenant_id',true),'')::uuid=$1::uuid"),
                authority_verify_authority_1: concat!($scope_admission_header),
                authority_verify_authority_2: concat!($scope_state_header),
                authority_verify_authority_3: concat!($channel_admission_header),
                group_change_admission: concat!(r###"WITH execution_roles AS (SELECT oid FROM pg_roles WHERE rolname=current_user OR pg_has_role(session_user,oid,'SET')), reachable AS (SELECT r.oid FROM pg_roles r WHERE EXISTS(SELECT 1 FROM execution_roles e WHERE pg_has_role(e.oid,r.oid,'USAGE')))
SELECT EXISTS(SELECT FROM pg_class c WHERE c.oid='"###, $group_changes, r###"'::regclass AND c.relkind='r'
 AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner NOT IN(SELECT oid FROM reachable)
 AND has_table_privilege(current_user,c.oid,'SELECT')
 AND has_table_privilege(current_user,c.oid,'INSERT')=$1::boolean
 AND NOT has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
  AND (has_column_privilege(current_user,c.oid,a.attnum,'UPDATE')<>(NOT $1::boolean AND a.attname IN('cursor','completed'))
    OR has_column_privilege(current_user,c.oid,a.attnum,'REFERENCES')))
 AND (SELECT count(*) FROM pg_policy WHERE polrelid=c.oid)=1
 AND EXISTS(SELECT FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
  AND lower(replace(regexp_replace(pg_get_expr(p.polqual,p.polrelid),'[[:space:]()]','','g'),'::text',''))='tenant_id=nullifcurrent_setting''rss.tenant_id'',true,''''::uuid'
  AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))
 AND NOT EXISTS(SELECT FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))
 AND NOT EXISTS(SELECT FROM pg_attribute col CROSS JOIN LATERAL aclexplode(col.attacl) a WHERE col.attrelid=c.oid AND (a.grantee=0 OR (a.grantee IN(SELECT oid FROM reachable) AND a.is_grantable))))
 AND NOT EXISTS(SELECT FROM pg_roles WHERE oid IN(SELECT oid FROM reachable) AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
"###),
                object_manifest: concat!(r###"{"tables":[""###, $asset_dispatch, r###"",""###, $group_changes, r###"",""###, $schema, r###"scope_channel_results",""###, $schema, r###"scope_projection_runs",""###, $schema, r###"scope_results",""###, $schema, r###"scope_runs",""###, $schema, r###"scope_source_members",""###, $schema, r###"scope_sources",""###, $schema, r###"scope_versions",""###, $schema, r###"scopes",""###, $tasks, r###"",""###, $operations, r###""],"functions":[""###, $schema, r###"channel_admission",""###, $schema, r###"guard_scope_channel_result",""###, $schema, r###"scope_admission",""###, $schema, r###"scope_state"],"views":[]}"###),
                access_contract: concat!(r###"{"tables":[],"functions":[{"name":""###, $schema, r###"scope_admission","search_path":"search_path=pg_catalog"},{"name":""###, $schema, r###"scope_state","search_path":"search_path=pg_catalog"},{"name":""###, $schema, r###"channel_admission","search_path":"search_path=pg_catalog"}],"external_relations":["###, $access_contract_external_relations, r###"],"verified_schemas":[]}"###),
                operation_lock: concat!("SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,'", $operations, "',$2::text,$3::text)::text,2889))"),
                operation_replay: concat!("SELECT fingerprint,response,instance::text FROM ", $operations, " WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3"),
                operation_receipt: concat!("INSERT INTO ", $operations, "(tenant_id,actor,id,fingerprint,response,instance) VALUES($1::uuid,$2,$3,$4,$5,$6::uuid)"),
                queue_counts: concat!(r###"SELECT
            (SELECT count(*) FROM (SELECT 1 FROM "###, $tasks, " t WHERE t.tenant_id=$1::uuid AND NOT completed AND NOT EXISTS(SELECT 1 FROM ", $schema, r###"scope_runs r WHERE(r.tenant_id,r.id)=(t.tenant_id,t.id)) LIMIT 1001) q),
            (SELECT count(*) FROM (SELECT 1 FROM "###, $tasks, " t WHERE t.tenant_id=$1::uuid AND NOT completed AND EXISTS(SELECT 1 FROM ", $schema, r###"scope_runs r WHERE(r.tenant_id,r.id)=(t.tenant_id,t.id)) LIMIT 1001) q),
            (SELECT count(*) FROM (SELECT 1 FROM "###, $tasks, r###" WHERE tenant_id=$1::uuid AND completed AND failure IS NULL LIMIT 1001) q),
            (SELECT count(*) FROM (SELECT 1 FROM "###, $tasks, r###" WHERE tenant_id=$1::uuid AND failure IS NOT NULL AND failure<>'superseded' LIMIT 1001) q),
            (SELECT count(*) FROM (SELECT 1 FROM "###, $tasks, " WHERE tenant_id=$1::uuid AND failure='superseded' LIMIT 1001) q)"),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_scope.",
    "SCHEMA mdm_scope",
    "'mdm_scope'",
    "mdm_access.",
    "mdm_access",
    "mdm_scope.tasks",
    "'tasks'",
    "mdm_scope.asset_dispatch",
    "'asset_dispatch'",
    "mdm_scope.group_changes",
    "'group_changes'",
    "mdm_owner",
    "mdm_command_runtime",
    "mdm_inventory_runtime",
    "mdm_scope_runtime",
    "mdm_policy_runtime",
    "mdm_telemetry_runtime",
    "CREATE FUNCTION mdm_scope.scope_admission(",
    "CREATE FUNCTION mdm_scope.scope_state(",
    "CREATE FUNCTION mdm_scope.channel_admission(",
    "CREATE SCHEMA IF NOT EXISTS mdm_scope",
    "mdm_identity_runtime",
    "mdm_resource_runtime",
    "mdm_software_runtime",
    "mdm_devices.object_current(e.input,p_channel)",
    "ADD CONSTRAINT scope_results_pkey",
    "ADD CONSTRAINT scope_runs_pkey",
    "ADD CONSTRAINT scope_source_members_pkey",
    "ADD CONSTRAINT scope_sources_pkey",
    "ADD CONSTRAINT scope_versions_pkey",
    "ADD CONSTRAINT scopes_pkey",
    "CREATE INDEX scope_results_members",
    "CREATE INDEX scope_source_members_devices",
    "CREATE INDEX scope_sources_target",
    "CREATE INDEX scope_source_members_channels",
    "CREATE UNIQUE INDEX scope_pending_task",
    "ADD CONSTRAINT scope_results_tenant_id_run_fkey",
    "ADD CONSTRAINT scope_runs_tenant_id_scope_fkey",
    "ADD CONSTRAINT scope_source_members_tenant_id_run_fkey",
    "ADD CONSTRAINT scope_sources_tenant_id_scope_fkey",
    "ADD CONSTRAINT scope_versions_tenant_id_id_fkey",
    "ADD CONSTRAINT scopes_tenant_id_resolution_fkey",
    "CREATE INDEX group_changes_pending",
    "CREATE INDEX scope_channel_results_cursor",
    r###""mdm_scope.scopes","mdm_scope.scope_runs","mdm_scope.scope_source_members","mdm_scope.scope_channel_results","mdm_scope.scope_projection_runs""###,
    "mdm_scope.operations",
    "'operations'"
);
define_storage!(
    da,
    "rss_da.",
    "SCHEMA rss_da",
    "'rss_da'",
    "rss_da.",
    "da_access",
    "rss_da.scope_tasks",
    "'scope_tasks'",
    "rss_da.scope_asset_dispatch",
    "'scope_asset_dispatch'",
    "rss_da.scope_group_changes",
    "'scope_group_changes'",
    "da_owner",
    "da_command_runtime",
    "da_inventory_runtime",
    "da_scope_runtime",
    "da_policy_runtime",
    "da_telemetry_runtime",
    "CREATE FUNCTION rss_da.scope_admission(",
    "CREATE FUNCTION rss_da.scope_state(",
    "CREATE FUNCTION rss_da.channel_admission(",
    "CREATE SCHEMA IF NOT EXISTS rss_da",
    "da_identity_runtime",
    "da_resource_runtime",
    "da_software_runtime",
    "CASE WHEN e.input#>>'{object,kind}'='endpoint' THEN rss_da.channel_members_current(e.input,p_channel) END",
    "ADD CONSTRAINT scope_scope_results_pkey",
    "ADD CONSTRAINT scope_scope_runs_pkey",
    "ADD CONSTRAINT scope_scope_source_members_pkey",
    "ADD CONSTRAINT scope_scope_sources_pkey",
    "ADD CONSTRAINT scope_scope_versions_pkey",
    "ADD CONSTRAINT scope_scopes_pkey",
    "CREATE INDEX scope_scope_results_members",
    "CREATE INDEX scope_scope_source_members_devices",
    "CREATE INDEX scope_scope_sources_target",
    "CREATE INDEX scope_scope_source_members_channels",
    "CREATE UNIQUE INDEX scope_scope_pending_task",
    "ADD CONSTRAINT scope_scope_results_tenant_id_run_fkey",
    "ADD CONSTRAINT scope_scope_runs_tenant_id_scope_fkey",
    "ADD CONSTRAINT scope_scope_source_members_tenant_id_run_fkey",
    "ADD CONSTRAINT scope_scope_sources_tenant_id_scope_fkey",
    "ADD CONSTRAINT scope_scope_versions_tenant_id_id_fkey",
    "ADD CONSTRAINT scope_scopes_tenant_id_resolution_fkey",
    "CREATE INDEX scope_group_changes_pending",
    "CREATE INDEX scope_scope_channel_results_cursor",
    r###""rss_da.scopes","rss_da.scope_runs","rss_da.scope_source_members","rss_da.scope_projection_runs","rss_da.scope_channel_results""###,
    "rss_da.scope_operations",
    "'scope_operations'"
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
