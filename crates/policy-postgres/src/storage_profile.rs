//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub migration: &'static str,
    pub outbox_migration: &'static str,
    pub relations: &'static str,
    pub authority_admission: &'static str,
    pub access_admission: &'static str,
    pub group_reference_facts: &'static str,
    pub telemetry_current_on_1: &'static str,
    pub telemetry_current_on_2: &'static str,
    pub telemetry_historical_on_1: &'static str,
    pub telemetry_candidates_on_1: &'static str,
    pub telemetry_is_current_on_1: &'static str,
    pub telemetry_is_current_on_2: &'static str,
    pub events_replay_in_1: &'static str,
    pub events_matching_policies_in_1: &'static str,
    pub events_insert_batch_in_1: &'static str,
    pub events_insert_member_in_1: &'static str,
    pub events_pending_member_in_1: &'static str,
    pub events_decide_member_in_1: &'static str,
    pub events_reject_next_in_1: &'static str,
    pub events_member_fact_in_1: &'static str,
    pub store_read_for_update_in_1: &'static str,
    pub store_publish_in_1: &'static str,
    pub store_publish_in_2: &'static str,
    pub store_replay_in_1: &'static str,
    pub store_receipt_in_1: &'static str,
    pub store_trigger_in_1: &'static str,
    pub store_read_snapshot_on_1: &'static str,
    pub store_version_snapshot_on_1: &'static str,
    pub resource_reference_facts: &'static str,
    pub store_resolve_in_1: &'static str,
    pub store_locked_in_1: &'static str,
    pub store_action_kinds_in_1: &'static str,
    pub scope_reference_facts: &'static str,
    pub scope_dependents_in_1: &'static str,
    pub schedules_triggers_in_1: &'static str,
    pub schedules_retirement_in_1: &'static str,
    pub schedules_scan_due_in_1: &'static str,
    pub schedules_scan_cursor_in_1: &'static str,
    pub schedules_scan_cursor_in_2: &'static str,
    pub schedules_complete_scan_in_1: &'static str,
    pub directory_policies_in_1: &'static str,
    pub directory_events_in_1: &'static str,
    pub directory_batch_exists_in_1: &'static str,
    pub candidates_native_interests_on_1: &'static str,
    pub candidates_configuration_candidates_on_1: &'static str,
    pub candidates_candidates_on_1: &'static str,
    pub work_enqueue_in_1: &'static str,
    pub work_read_in_1: &'static str,
    pub work_cursor_in_1: &'static str,
    pub work_pending_in_1: &'static str,
    pub work_forwarded_in_1: &'static str,
    pub work_finish_in_1: &'static str,
    pub work_exists_in_1: &'static str,
    pub work_replacement_in_1: &'static str,
    pub work_counts_in_1: &'static str,
    pub work_inputs_pending_in_1: &'static str,
    pub assignments_upsert_in_1: &'static str,
    pub assignments_objects_in_1: &'static str,
    pub assignments_withdraw_in_1: &'static str,
    pub object_manifest: &'static str,
    pub access_contract: &'static str,
    pub directory_event_batches: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $policies:literal, $versions:literal, $assignments:literal, $triggers:literal, $requests:literal, $work:literal, $schedule_scan:literal, $event_batches:literal, $event_members:literal, $policy_schema:literal, $policy_schema_decl:literal, $policy_role:literal, $access:literal, $owner:literal, $command:literal, $telemetry:literal, $scope:literal, $create_mdm_policy:literal, $role_mdm_identity_runtime:literal, $role_mdm_inventory_runtime:literal, $role_mdm_scope_runtime:literal, $role_mdm_resource_runtime:literal, $role_mdm_software_runtime:literal, $index_23:literal, $index_24:literal, $index_25:literal, $index_26:literal, $index_27:literal, $index_28:literal, $index_29:literal, $index_30:literal, $index_31:literal, $access_contract_external_relations:literal, $tenant_reference:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                migration: concat!(r###"BEGIN;
"###, $create_mdm_policy, r###";
REVOKE ALL ON "###, $policy_schema_decl, r###" FROM PUBLIC;
CREATE TABLE "###, $policies, r###" (
 tenant_id uuid NOT NULL, id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 current_version uuid NOT NULL, version_number bigint NOT NULL CHECK(version_number>0),
 execution_binding bytea CHECK(execution_binding IS NULL OR octet_length(execution_binding)=32),
 state text NOT NULL CHECK(state IN ('enabled','disabled','archived')), definition jsonb NOT NULL CHECK(octet_length(definition::text)<=4194304),
 CHECK(definition->'action'->>'kind'<>'software' OR coalesce(definition->'action'->>'channel' IN ('agent','mdm'),false)),
 author jsonb NOT NULL, updated_at bigint NOT NULL CHECK(updated_at>=0), PRIMARY KEY(tenant_id,id)
);
CREATE TABLE "###, $versions, r###" (
 tenant_id uuid NOT NULL,id uuid NOT NULL,policy uuid NOT NULL,number bigint NOT NULL CHECK(number>0),
 action_kind text NOT NULL CHECK(action_kind IN ('device_access','credential','execution','agent_collection','telemetry_profile','native_collection','configuration','software','ensure_agent_installed','request_mdm_enrollment','unmanage_device')),
 resource text,resource_version text,
 CHECK((resource IS NULL) = (resource_version IS NULL)),
 CHECK((action_kind IN ('device_access','credential','ensure_agent_installed','request_mdm_enrollment','unmanage_device')) = (resource IS NULL)),
 frozen jsonb NOT NULL CHECK(octet_length(frozen::text)<=25165824),
 CHECK(action_kind<>'software' OR coalesce(frozen->'action'->>'channel' IN ('agent','mdm'),false)),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,policy,number),
 FOREIGN KEY(tenant_id,policy) REFERENCES "###, $policies, r###"(tenant_id,id)
);
CREATE INDEX ON "###, $versions, r###"(tenant_id,resource,resource_version,policy,id);
ALTER TABLE "###, $policies, " ADD FOREIGN KEY(tenant_id,current_version) REFERENCES ", $versions, r###"(tenant_id,id) DEFERRABLE INITIALLY DEFERRED;
"###, $index_23, " ON ", $policies, r###"(tenant_id, (definition->>'alias')) WHERE state<>'archived' AND definition->>'alias' IS NOT NULL;
"###, $index_24, " ON ", $policies, r###"(tenant_id, (definition->>'customEvent'), id) WHERE state<>'archived' AND definition->>'customEvent' IS NOT NULL;
"###, $index_25, " ON ", $policies, r###"(tenant_id,((definition->>'scope')::uuid),id);
CREATE TABLE "###, $triggers, r###" (
 tenant_id uuid NOT NULL,id uuid NOT NULL,version uuid NOT NULL,created_at bigint NOT NULL,deadline bigint NOT NULL CHECK(deadline>created_at),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,version) REFERENCES "###, $versions, r###"(tenant_id,id)
);
"###, $index_26, " ON ", $triggers, r###"(tenant_id,version,deadline,created_at,id);

CREATE TABLE "###, $schedule_scan, r###" (
 tenant_id uuid PRIMARY KEY, after_policy uuid, next_scan_at bigint NOT NULL DEFAULT 0 CHECK(next_scan_at>=0)
);
CREATE TABLE "###, $requests, r###" (
 tenant_id uuid NOT NULL,id uuid NOT NULL,fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),receipt jsonb NOT NULL CHECK(octet_length(receipt::text)<=16777216),PRIMARY KEY(tenant_id,id)
);
ALTER TABLE "###, $policies, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $policies, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $policies, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $policies, " TO ", $policy_role, r###";
ALTER TABLE "###, $versions, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $versions, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $versions, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $versions, " TO ", $policy_role, r###";
ALTER TABLE "###, $triggers, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $triggers, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $triggers, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $triggers, " TO ", $policy_role, r###";
ALTER TABLE "###, $requests, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $requests, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $requests, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $requests, " TO ", $policy_role, r###";
ALTER TABLE "###, $schedule_scan, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $schedule_scan, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $schedule_scan, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $schedule_scan, " TO ", $policy_role, r###";
GRANT USAGE ON "###, $policy_schema_decl, " TO ", $policy_role, r###";
GRANT UPDATE(after_policy,next_scan_at) ON "###, $schedule_scan, " TO ", $policy_role, r###";
GRANT UPDATE(revision,current_version,version_number,state,definition,author,updated_at,execution_binding) ON "###, $policies, " TO ", $policy_role, r###";
-- Policy application data; installation only, never runtime DDL.
CREATE FUNCTION "###, $policy_schema, r###"lock_policy(p_policy uuid) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
 SELECT FROM "###, $policies, r###" WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND id=p_policy FOR SHARE;
$$;
REVOKE ALL ON FUNCTION "###, $policy_schema, r###"lock_policy(uuid) FROM PUBLIC;
CREATE TABLE "###, $work, r###" (
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
    CONSTRAINT policy_work_authority_revision_check CHECK ((authority_revision >= 0)),
    CONSTRAINT policy_work_failure_check CHECK ((failure = ANY (ARRAY['superseded'::text, 'capacity_exceeded'::text, 'source_unavailable'::text, 'invalid_input'::text, 'storage_invariant'::text, 'automation_suspended'::text, 'configuration_target_limit'::text, 'capability_unknown'::text, 'platform_unsupported'::text, 'stale_plan'::text, 'owner_conflict'::text, 'permission_denied'::text]))),
    CONSTRAINT policy_work_input_check CHECK ((octet_length((input)::text) <= 1048576)),
    CONSTRAINT policy_work_kind_check CHECK ((kind = ANY (ARRAY['policy_scope'::text, 'policy_reconcile'::text, 'policy_event'::text, 'policy_lifecycle'::text]))),
    CONSTRAINT policy_work_target_check CHECK (((octet_length(target) >= 1) AND (octet_length(target) <= 256)))
);

ALTER TABLE ONLY "###, $work, r###" FORCE ROW LEVEL SECURITY;

ALTER TABLE ONLY "###, $work, r###"
    "###, $index_27, r###" PRIMARY KEY (tenant_id, id);

"###, $index_28, " ON ", $work, r###" USING btree (tenant_id, id) WHERE (NOT forwarded);

ALTER TABLE "###, $work, r###" ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $work, r###" USING ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)) WITH CHECK ((tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid));

CREATE TABLE "###, $event_batches, r###" (
 tenant_id uuid NOT NULL, id uuid NOT NULL, request uuid NOT NULL, actor text NOT NULL,
 caller jsonb NOT NULL, device text NOT NULL, input jsonb NOT NULL,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 created_at bigint NOT NULL, deadline bigint NOT NULL CHECK(deadline>created_at),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,actor,request)
);

CREATE TABLE "###, $event_members, r###" (
 tenant_id uuid NOT NULL,batch uuid NOT NULL,id uuid NOT NULL,policy uuid NOT NULL,
 revision bigint NOT NULL,version uuid NOT NULL,target jsonb NOT NULL,authority jsonb NOT NULL,decision jsonb NOT NULL,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,batch,policy),
 FOREIGN KEY(tenant_id,batch) REFERENCES "###, $event_batches, r###"(tenant_id,id)
);

"###, $index_29, " ON ", $event_members, r###"(tenant_id,batch,id) WHERE decision->>'state'='pending';

"###, $index_30, " ON ", $event_batches, r###"(tenant_id,device,id);

ALTER TABLE "###, $event_batches, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $event_batches, r###" FORCE ROW LEVEL SECURITY;

ALTER TABLE "###, $event_members, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $event_members, r###" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $event_batches, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY tenant ON "###, $event_members, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);




CREATE TABLE "###, $assignments, r###" (
 tenant_id uuid NOT NULL, policy uuid NOT NULL, version uuid NOT NULL,
 entry_revision bigint NOT NULL CHECK(entry_revision>=0),
 object text COLLATE "C" NOT NULL, channel text NOT NULL CHECK(channel IN('agent','mdm')),
 input jsonb NOT NULL, availability text NOT NULL CHECK(availability IN('ready','unavailable')),
 reason text, target jsonb, scope_result uuid NOT NULL,
 PRIMARY KEY(tenant_id,policy,version,object,channel),
 FOREIGN KEY(tenant_id,version) REFERENCES "###, $versions, r###"(tenant_id,id),
 CHECK((availability='ready')=(reason IS NULL)), CHECK(availability<>'ready' OR target IS NOT NULL)
);
"###, $index_31, " ON ", $assignments, r###"(tenant_id,(target->>'device'),policy,version) WHERE channel='mdm';
ALTER TABLE "###, $assignments, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $assignments, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $assignments, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON "###, $assignments, ",", $work, ",", $event_batches, ",", $event_members, " TO ", $policy_role, r###";
GRANT UPDATE(input,availability,reason,target,scope_result,entry_revision) ON "###, $assignments, " TO ", $policy_role, r###";
GRANT UPDATE(forwarded,completed,cursor,replacement_task,authority_revision,failure,failure_detail) ON "###, $work, " TO ", $policy_role, r###";
GRANT UPDATE(decision) ON "###, $event_members, " TO ", $policy_role, r###";

COMMIT;
"###),
                outbox_migration: concat!(r###"-- Public Outbox writer admission; existing product schema units stay immutable.
BEGIN;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO "###, $policy_role, r###";
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO "###, $policy_role, r###";
REVOKE INSERT ON rss_transactional_messaging.outbox FROM "###, $policy_role, r###";
REVOKE ALL ON SEQUENCE rss_transactional_messaging.outbox_seq_seq FROM "###, $policy_role, r###";
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution(),
 rss_transactional_messaging.prepare_outbox_partitions(jsonb),
 rss_transactional_messaging.append_outbox(bytea,jsonb) TO "###, $policy_role, r###";
COMMIT;
"###),
                relations: concat!(r###"-- Foreign references and precise consumers of Policy-owned facts.
BEGIN;
ALTER TABLE "###, $assignments, " ADD FOREIGN KEY(tenant_id) ", $tenant_reference, r###";
ALTER TABLE "###, $assignments, " ADD FOREIGN KEY(tenant_id,scope_result) REFERENCES ", $scope, r###"scope_runs(tenant_id,id);
GRANT USAGE ON "###, $policy_schema_decl, " TO ", $command, r###";
GRANT EXECUTE ON FUNCTION "###, $policy_schema, "lock_policy(uuid) TO ", $policy_role, ",", $telemetry, ",", $command, ",", $access, r###";
GRANT SELECT ON "###, $policies, ",", $versions, ",", $triggers, ",", $assignments, " TO ", $command, r###";
GRANT SELECT ON "###, $policies, ",", $versions, " TO ", $access, r###";
GRANT SELECT,INSERT ON "###, $event_batches, ",", $event_members, ",", $work, " TO ", $command, r###";
GRANT UPDATE(decision) ON "###, $event_members, " TO ", $command, r###";
GRANT UPDATE(completed,failure) ON "###, $work, " TO ", $command, r###";
GRANT SELECT,INSERT ON "###, $assignments, ",", $work, " TO ", $policy_role, r###";
GRANT UPDATE(input,availability,reason,target,scope_result,entry_revision) ON "###, $assignments, " TO ", $policy_role, r###";
GRANT UPDATE(forwarded,completed,cursor,replacement_task,authority_revision,failure,failure_detail) ON "###, $work, " TO ", $policy_role, r###";
COMMIT;

GRANT SELECT,INSERT ON "###, $schedule_scan, " TO ", $policy_role, r###";
GRANT UPDATE(after_policy,next_scan_at) ON "###, $schedule_scan, " TO ", $policy_role, r###";

-- Explicit integration privileges owned by this capability.
GRANT USAGE ON "###, $policy_schema_decl, " TO ", $policy_role, r###";

GRANT USAGE ON "###, $policy_schema_decl, " TO ", $access, r###";

GRANT USAGE ON "###, $policy_schema_decl, " TO ", $role_mdm_inventory_runtime, ",", $role_mdm_scope_runtime, ",", $role_mdm_resource_runtime, ",", $role_mdm_software_runtime, ",", $telemetry, r###";
GRANT SELECT ON "###, $policies, ",", $versions, ",", $assignments, " TO ", $role_mdm_inventory_runtime, ",", $role_mdm_scope_runtime, ",", $role_mdm_resource_runtime, ",", $role_mdm_software_runtime, ",", $telemetry, r###";
GRANT SELECT,INSERT ON "###, $work, " TO ", $role_mdm_scope_runtime, r###";
"###),
                authority_admission: concat!(r###"-- Privileged kernels: exact bodies come from the corresponding owner's installation SQL.
WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES
 ('"###, $policy_schema, "lock_policy(uuid)', 'sql', 'void', true, false, 'v', ARRAY['p_policy']::text[], ARRAY['search_path=pg_catalog']::text[], $1::text, ARRAY['", $access, "','", $command, "','", $policy_role, "','", $telemetry, "','", $role_mdm_identity_runtime, "','", $owner, r###"']::text[])
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
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
 WHERE a.grantee=0 OR (a.grantee<>p.proowner AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT pg_get_userbyid(a.grantee)=ANY(e.roles))))
ORDER BY e.signature LIMIT 1
"###),
                access_admission: concat!(r###"-- The native registration transaction can inspect frozen execution authority, never mutate it.
WITH expected(name) AS (VALUES ('"###, $policies, "'),('", $versions, r###"')
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
                group_reference_facts: concat!(r###"
SELECT tenant_id,id,revision,state,(definition->>'scope')::uuid AS scope_id,
 ARRAY(SELECT DISTINCT (stage->>'scope')::uuid FROM jsonb_array_elements(coalesce(definition#>'{action,rollout,stages}','[]')) stage ORDER BY (stage->>'scope')::uuid) AS rollout_scope_ids
FROM "###, $policies, r###" WHERE tenant_id=$1::uuid
"###),
                telemetry_current_on_1: concat!("SELECT ", $policy_schema, "lock_policy($1)"),
                telemetry_current_on_2: concat!("SELECT p.definition,v.frozen FROM ", $policies, " p JOIN ", $versions, " v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.id=$2 AND p.current_version=$3 AND p.state='enabled' AND v.action_kind='telemetry_profile'"),
                telemetry_historical_on_1: concat!("SELECT frozen FROM ", $versions, " WHERE tenant_id=$1::uuid AND policy=$2 AND id=$3 AND action_kind='telemetry_profile'"),
                telemetry_candidates_on_1: concat!("SELECT p.id,p.current_version,p.definition FROM ", $policies, " p JOIN ", $versions, " v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND v.action_kind='telemetry_profile' ORDER BY p.id LIMIT 257"),
                telemetry_is_current_on_1: concat!("SELECT ", $policy_schema, "lock_policy($1)"),
                telemetry_is_current_on_2: concat!("SELECT true FROM ", $policies, " WHERE tenant_id=$1::uuid AND id=$2 AND current_version=$3 AND state='enabled'"),
                events_replay_in_1: concat!("SELECT fingerprint,id,(SELECT count(*) FROM ", $event_members, " m WHERE(m.tenant_id,m.batch)=(b.tenant_id,b.id)) FROM ", $event_batches, " b WHERE tenant_id=$1::uuid AND actor=$2 AND request=$3"),
                events_matching_policies_in_1: concat!("SELECT id FROM ", $policies, " WHERE tenant_id=$1::uuid AND definition->>'customEvent'=$2 AND state<>'archived' ORDER BY id LIMIT 1001"),
                events_insert_batch_in_1: concat!("INSERT INTO ", $event_batches, "(tenant_id,id,request,actor,caller,device,input,fingerprint,created_at,deadline) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)"),
                events_insert_member_in_1: concat!("INSERT INTO ", $event_members, "(tenant_id,batch,id,policy,revision,version,target,authority,decision) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)"),
                events_pending_member_in_1: concat!("SELECT b.caller,b.input,b.deadline,m.id,m.policy,m.version,m.target,m.authority FROM ", $event_batches, " b JOIN ", $event_members, " m ON(m.tenant_id,m.batch)=(b.tenant_id,b.id) WHERE b.tenant_id=$1::uuid AND b.id=$2 AND m.decision->>'state'='pending' ORDER BY m.id LIMIT 1 FOR UPDATE OF m"),
                events_decide_member_in_1: concat!("UPDATE ", $event_members, " SET decision=$3 WHERE tenant_id=$1::uuid AND id=$2"),
                events_reject_next_in_1: concat!("UPDATE ", $event_members, " SET decision=$3 WHERE tenant_id=$1::uuid AND id=(SELECT id FROM ", $event_members, " WHERE tenant_id=$1::uuid AND batch=$2 AND decision->>'state'='pending' ORDER BY id LIMIT 1) RETURNING id"),
                events_member_fact_in_1: concat!("SELECT m.target,m.policy,m.version,b.request,b.input FROM ", $event_members, " m JOIN ", $event_batches, " b ON(b.tenant_id,b.id)=(m.tenant_id,m.batch) WHERE m.tenant_id=$1::uuid AND m.id=$2"),
                store_read_for_update_in_1: concat!("SELECT id FROM ", $policies, " WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                store_publish_in_1: concat!("INSERT INTO ", $policies, "(tenant_id,id,revision,current_version,version_number,state,definition,author,updated_at,execution_binding) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,current_version=excluded.current_version,version_number=excluded.version_number,state=excluded.state,definition=excluded.definition,author=excluded.author,updated_at=excluded.updated_at,execution_binding=excluded.execution_binding"),
                store_publish_in_2: concat!("INSERT INTO ", $versions, "(tenant_id,id,policy,number,resource,resource_version,frozen,fingerprint,action_kind) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)"),
                store_replay_in_1: concat!("SELECT fingerprint,receipt FROM ", $requests, " WHERE tenant_id=$1::uuid AND id=$2"),
                store_receipt_in_1: concat!("INSERT INTO ", $requests, " VALUES($1::uuid,$2,$3,$4)"),
                store_trigger_in_1: concat!("INSERT INTO ", $triggers, "(tenant_id,id,version,created_at,deadline) VALUES($1::uuid,$2,$3,$4,$5)"),
                store_read_snapshot_on_1: concat!("SELECT revision,current_version,version_number,state,definition,execution_binding FROM ", $policies, " WHERE tenant_id=$1::uuid AND id=$2"),
                store_version_snapshot_on_1: concat!("SELECT policy,number,action_kind,frozen FROM ", $versions, " WHERE tenant_id=$1::uuid AND id=$2"),
                resource_reference_facts: concat!("SELECT v.policy::text AS id,v.id::text AS version,(p.current_version=v.id) AS current FROM ", $versions, " v JOIN ", $policies, " p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE v.tenant_id=$1::uuid AND v.resource=$2 AND v.resource_version=$3"),
                store_resolve_in_1: concat!("SELECT id FROM ", $policies, " WHERE tenant_id=$1::uuid AND definition->>'alias'=$2 AND state<>'archived'"),
                store_locked_in_1: concat!("SELECT ", $policy_schema, "lock_policy($1)"),
                store_action_kinds_in_1: concat!("SELECT DISTINCT action_kind FROM ", $versions, " WHERE tenant_id=$1::uuid AND policy=$2 ORDER BY action_kind"),
                scope_reference_facts: concat!("SELECT id,current_version AS version,revision,state,ARRAY(SELECT role FROM (SELECT 'policy_scope'::text AS role WHERE (definition->>'scope')::uuid=$2 UNION ALL SELECT 'rollout_stage' WHERE EXISTS(SELECT FROM jsonb_array_elements(coalesce(definition#>'{action,rollout,stages}','[]'::jsonb)) stage WHERE (stage->>'scope')::uuid=$2)) roles FROM ", $policies, " WHERE tenant_id=$1::uuid AND ((definition->>'scope')::uuid=$2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(definition->'action'->'rollout'->'stages','[]'::jsonb)) stage WHERE (stage->>'scope')::uuid=$2))"),
                scope_dependents_in_1: concat!("SELECT id FROM ", $policies, " WHERE tenant_id=$1::uuid AND (definition->>'scope'=$2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(definition->'action'->'rollout'->'stages','[]'::jsonb)) stage WHERE stage->>'scope'=$2)) AND id>coalesce($3::uuid,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY id LIMIT 65"),
                schedules_triggers_in_1: concat!("SELECT id,created_at FROM ", $triggers, " WHERE tenant_id=$1::uuid AND version=$2 AND deadline>$3 ORDER BY created_at DESC,id DESC LIMIT 64"),
                schedules_retirement_in_1: concat!("SELECT p.id,v.id,v.frozen FROM ", $policies, " p JOIN ", $versions, " v ON(v.tenant_id,v.id)=(p.tenant_id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND v.action_kind='unmanage_device' AND ($2::uuid IS NULL OR p.id>$2) ORDER BY p.id LIMIT 64"),
                schedules_scan_due_in_1: concat!("SELECT coalesce((SELECT next_scan_at FROM ", $schedule_scan, " WHERE tenant_id=$1::uuid),0)<=$2"),
                schedules_scan_cursor_in_1: concat!("INSERT INTO ", $schedule_scan, "(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING"),
                schedules_scan_cursor_in_2: concat!("SELECT after_policy FROM ", $schedule_scan, " WHERE tenant_id=$1::uuid FOR UPDATE"),
                schedules_complete_scan_in_1: concat!("UPDATE ", $schedule_scan, " SET after_policy=$2,next_scan_at=$3 WHERE tenant_id=$1::uuid"),
                directory_policies_in_1: concat!("SELECT jsonb_build_object('id',id,'toolName','policy_' || replace(id::text,'-',''),'alias',definition->>'alias','customEvent',definition->>'customEvent','revision',revision,'version',version_number,'versionId',current_version,'state',state,'definition',definition,'action',definition->'action'->>'kind','scope',definition->>'scope','resource',definition->'action'->'resource'->>'id','category',definition->'selfService'->'presentation'->>'category') FROM ", $policies, " WHERE tenant_id="),
                directory_events_in_1: concat!("SELECT jsonb_build_object('id',m.id,'policyId',m.policy,'versionId',m.version,'revision',m.revision,'state',m.decision->>'state','decision',m.decision) FROM ", $event_members, " m JOIN ", $event_batches, " b ON(b.tenant_id,b.id)=(m.tenant_id,m.batch) WHERE b.tenant_id="),
                directory_batch_exists_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $event_batches, " WHERE tenant_id=$1::uuid AND id=$2 AND device=$3)"),
                candidates_native_interests_on_1: concat!("SELECT DISTINCT a.target->>'device' FROM ", $policies, " p JOIN ", $assignments, " a ON(a.tenant_id,a.policy,a.version)=(p.tenant_id,p.id,p.current_version) WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND p.definition->'action'->>'kind'=ANY($3::text[]) AND (p.definition->'action'->>'kind'<>'software' OR p.definition->'action'->>'channel'='mdm') AND a.channel='mdm' AND a.target->>'device'=ANY($2::text[]) AND a.input->'admission'->>'state'<>'excluded' ORDER BY 1"),
                candidates_configuration_candidates_on_1: concat!("WITH candidates AS MATERIALIZED (SELECT p.id,p.current_version,(p.definition->>'scope')::uuid AS scope,d.device FROM ", $policies, r###" p CROSS JOIN (SELECT DISTINCT unnest($2::text[]) AS device) d WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND p.definition->'action'->>'kind'='configuration' AND ($3::uuid IS NULL OR (p.id,d.device COLLATE "C")>($3,$4 COLLATE "C")) ORDER BY p.id,d.device COLLATE "C" LIMIT 1001) SELECT *,"###, $scope, r###"channel_admission(scope,'mdm',device) AS admission FROM candidates ORDER BY id,device COLLATE "C""###),
                candidates_candidates_on_1: concat!("SELECT id,current_version,(definition->>'scope')::uuid AS scope FROM ", $policies, " WHERE tenant_id=$1::uuid AND (state='enabled') AND id>$2 AND definition->'action'->>'kind'=$3 ORDER BY id LIMIT 17"),
                work_enqueue_in_1: concat!("INSERT INTO ", $work, "(tenant_id,id,kind,target,input) VALUES($1::uuid,$2,$3,$4,$5)"),
                work_read_in_1: concat!("SELECT input,completed,failure,cursor,forwarded FROM ", $work, " WHERE tenant_id=$1::uuid AND id=$2"),
                work_cursor_in_1: concat!("UPDATE ", $work, " SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2"),
                work_pending_in_1: concat!("SELECT id::text,kind FROM ", $work, " WHERE tenant_id=$1::uuid AND NOT forwarded ORDER BY id LIMIT 64"),
                work_forwarded_in_1: concat!("UPDATE ", $work, " SET forwarded=true WHERE tenant_id=$1::uuid AND id=$2 AND NOT forwarded"),
                work_finish_in_1: concat!("UPDATE ", $work, " SET completed=true,failure=$3 WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed RETURNING target,kind"),
                work_exists_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $work, " WHERE tenant_id=$1::uuid AND id=$2 AND (NOT $3 OR completed))"),
                work_replacement_in_1: concat!("UPDATE ", $work, " SET replacement_task=$3 WHERE tenant_id=$1::uuid AND id=$2"),
                work_counts_in_1: concat!("SELECT (SELECT count(*) FROM(SELECT 1 FROM ", $work, " WHERE tenant_id=$1::uuid AND failure IS NULL AND NOT completed AND NOT forwarded LIMIT 1001) q),(SELECT count(*) FROM(SELECT 1 FROM ", $work, " WHERE tenant_id=$1::uuid AND failure IS NULL AND NOT completed AND forwarded LIMIT 1001) q),(SELECT count(*) FROM(SELECT 1 FROM ", $work, " WHERE tenant_id=$1::uuid AND failure IS NULL AND completed LIMIT 1001) q),(SELECT count(*) FROM(SELECT 1 FROM ", $work, " WHERE tenant_id=$1::uuid AND failure IS NOT NULL AND failure<>'superseded' LIMIT 1001) q),(SELECT count(*) FROM(SELECT 1 FROM ", $work, " WHERE tenant_id=$1::uuid AND failure='superseded' LIMIT 1001) q)"),
                work_inputs_pending_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $work, " WHERE tenant_id=$1::uuid AND NOT forwarded)"),
                assignments_upsert_in_1: concat!("INSERT INTO ", $assignments, " AS current_assignment(tenant_id,policy,version,object,channel,input,availability,reason,target,scope_result,entry_revision) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant_id,policy,version,object,channel) DO UPDATE SET input=EXCLUDED.input,availability=EXCLUDED.availability,reason=EXCLUDED.reason,target=EXCLUDED.target,scope_result=EXCLUDED.scope_result,entry_revision=EXCLUDED.entry_revision WHERE (current_assignment.input,current_assignment.availability,current_assignment.reason,current_assignment.target,current_assignment.scope_result,current_assignment.entry_revision) IS DISTINCT FROM (EXCLUDED.input,EXCLUDED.availability,EXCLUDED.reason,EXCLUDED.target,EXCLUDED.scope_result,EXCLUDED.entry_revision)"),
                assignments_objects_in_1: concat!("SELECT object,input->'object' FROM ", $assignments, " WHERE tenant_id=$1::uuid AND policy=$2 AND version=$3 AND reason IS DISTINCT FROM 'source_removed'"),
                assignments_withdraw_in_1: concat!("UPDATE ", $assignments, r###" SET input=jsonb_set(jsonb_set(jsonb_set(input,'{availability}','"unavailable"'),'{reason}','"source_removed"'),'{admission}','{"state":"excluded"}'),availability='unavailable',reason='source_removed',entry_revision=0 WHERE tenant_id=$1::uuid AND policy=$2 AND version=$3 AND object=ANY($4::text[]) AND reason IS DISTINCT FROM 'source_removed' RETURNING object,target"###),
                object_manifest: concat!(r###"{"tables":[""###, $assignments, r###"",""###, $event_batches, r###"",""###, $event_members, r###"",""###, $policies, r###"",""###, $requests, r###"",""###, $schedule_scan, r###"",""###, $triggers, r###"",""###, $versions, r###"",""###, $work, r###""],"functions":[""###, $policy_schema, r###"lock_policy"],"views":[]}"###),
                access_contract: concat!(r###"{"tables":[],"functions":[{"name":""###, $policy_schema, r###"lock_policy","search_path":"search_path=pg_catalog"}],"external_relations":["###, $access_contract_external_relations, r###"],"verified_schemas":[]}"###),
                directory_event_batches: concat!("SELECT jsonb_build_object('request',b.input,'id',b.id,'operationId',b.request,'event',b.input->>'event','createdAt',b.created_at,'deadline',b.deadline,'processingFailure',(SELECT failure FROM ", $work, " WHERE tenant_id=b.tenant_id AND id=b.id),'members',(SELECT count(*) FROM ", $event_members, " m WHERE(m.tenant_id,m.batch)=(b.tenant_id,b.id)),'admission',(SELECT coalesce(jsonb_object_agg(state,n),'{}'::jsonb) FROM(SELECT decision->>'state' state,count(*) n FROM ", $event_members, " WHERE tenant_id=b.tenant_id AND batch=b.id GROUP BY decision->>'state') counts)) FROM ", $event_batches, " b WHERE b.tenant_id="),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_policy.policies",
    "mdm_policy.versions",
    "mdm_policy.assignments",
    "mdm_policy.triggers",
    "mdm_policy.requests",
    "mdm_policy.work",
    "mdm_policy.schedule_scan",
    "mdm_policy.event_batches",
    "mdm_policy.event_members",
    "mdm_policy.",
    "SCHEMA mdm_policy",
    "mdm_policy_runtime",
    "mdm_access",
    "mdm_owner",
    "mdm_command_runtime",
    "mdm_telemetry_runtime",
    "mdm_scope.",
    "CREATE SCHEMA IF NOT EXISTS mdm_policy",
    "mdm_identity_runtime",
    "mdm_inventory_runtime",
    "mdm_scope_runtime",
    "mdm_resource_runtime",
    "mdm_software_runtime",
    "CREATE UNIQUE INDEX policy_alias_unique",
    "CREATE INDEX policy_custom_event",
    "CREATE INDEX policy_scope",
    "CREATE INDEX policy_triggers_due",
    "ADD CONSTRAINT policy_work_pkey",
    "CREATE INDEX policy_work_pending",
    "CREATE INDEX event_members_pending",
    "CREATE INDEX event_batches_device",
    "CREATE INDEX assignment_device_interest",
    r###""mdm_policy.policies","mdm_policy.versions""###,
    "REFERENCES public.mdm_tenants(tenant_id)"
);
define_storage!(
    da,
    "rss_da.policies",
    "rss_da.policy_versions",
    "rss_da.policy_assignments",
    "rss_da.policy_triggers",
    "rss_da.policy_requests",
    "rss_da.policy_work",
    "rss_da.policy_schedule_scan",
    "rss_da.policy_event_batches",
    "rss_da.policy_event_members",
    "rss_da.",
    "SCHEMA rss_da",
    "da_policy_runtime",
    "da_access",
    "da_owner",
    "da_command_runtime",
    "da_telemetry_runtime",
    "rss_da.",
    "CREATE SCHEMA IF NOT EXISTS rss_da",
    "da_identity_runtime",
    "da_inventory_runtime",
    "da_scope_runtime",
    "da_resource_runtime",
    "da_software_runtime",
    "CREATE UNIQUE INDEX policy_policy_alias_unique",
    "CREATE INDEX policy_policy_custom_event",
    "CREATE INDEX policy_policy_scope",
    "CREATE INDEX policy_policy_triggers_due",
    "ADD CONSTRAINT policy_policy_work_pkey",
    "CREATE INDEX policy_policy_work_pending",
    "CREATE INDEX policy_event_members_pending",
    "CREATE INDEX policy_event_batches_device",
    "CREATE INDEX policy_assignment_device_interest",
    r###""rss_da.policies","rss_da.policy_versions""###,
    "REFERENCES rss_transactional_messaging.tenant_epoch(tenant_id)"
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
