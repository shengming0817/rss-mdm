//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub retention_material: &'static str,
    pub install: &'static str,
    pub tasks: &'static str,
    pub task_admission: &'static str,
    pub service_disclose_inner_1: &'static str,
    pub service_revoke_1: &'static str,
    pub service_revoke_2: &'static str,
    pub service_revoke_3: &'static str,
    pub service_revoke_4: &'static str,
    pub service_read_locked_1: &'static str,
    pub service_read_locked_2: &'static str,
    pub service_disclosure_receipt_1: &'static str,
    pub directory_read_1: &'static str,
    pub directory_read_2: &'static str,
    pub storage_rss_use_in_1: &'static str,
    pub storage_rss_use_in_2: &'static str,
    pub storage_rss_use_in_3: &'static str,
    pub storage_rss_use_in_4: &'static str,
    pub storage_reserve_in_1: &'static str,
    pub storage_reserve_in_2: &'static str,
    pub storage_reserve_in_3: &'static str,
    pub storage_reserve_in_4: &'static str,
    pub storage_reserve_in_5: &'static str,
    pub storage_reserve_in_6: &'static str,
    pub storage_reserve_in_7: &'static str,
    pub storage_ingest_in_1: &'static str,
    pub storage_locked_version_1: &'static str,
    pub storage_verify_in_1: &'static str,
    pub storage_verify_in_2: &'static str,
    pub storage_verify_in_3: &'static str,
    pub storage_verify_in_4: &'static str,
    pub storage_unknown_in_1: &'static str,
    pub storage_retire_in_1: &'static str,
    pub storage_retire_in_2: &'static str,
    pub storage_native_action_in_1: &'static str,
    pub storage_link_native_in_1: &'static str,
    pub storage_coordinates_in_1: &'static str,
    pub storage_settled_in_1: &'static str,
    pub storage_validate_keys_in_1: &'static str,
    pub storage_prepare_rewrap_in_1: &'static str,
    pub storage_rewrap_in_1: &'static str,
    pub storage_expired_in_1: &'static str,
    pub storage_clear_expired_in_1: &'static str,
    pub storage_verify_existing_secret_in_1: &'static str,
    pub storage_link_agent_in_1: &'static str,
    pub storage_link_agent_in_2: &'static str,
    pub storage_agent_materials_in_1: &'static str,
    pub storage_supersede_in_1: &'static str,
    pub storage_supersede_in_2: &'static str,
    pub storage_supersede_in_3: &'static str,
    pub storage_start_agent_in_1: &'static str,
    pub storage_start_agent_in_2: &'static str,
    pub storage_finish_agent_in_1: &'static str,
    pub storage_cleared_in_1: &'static str,
    pub storage_cleared_in_2: &'static str,
    pub storage_cleared_in_3: &'static str,
    pub storage_revisions_in_1: &'static str,
    pub storage_uncertain_version_in_1: &'static str,
    pub storage_input_copies_in_1: &'static str,
    pub storage_input_purged_in_1: &'static str,
    pub storage_inputs_remain_in_1: &'static str,
    pub storage_agent_guard_in_1: &'static str,
    pub storage_reconcile_in_1: &'static str,
    pub storage_reconcile_in_2: &'static str,
    pub storage_reconcile_in_3: &'static str,
    pub storage_reconcile_in_4: &'static str,
    pub storage_recovery_secret_in_1: &'static str,
    pub storage_cleanup_visited_in_1: &'static str,
    pub storage_current_in_1: &'static str,
    pub storage_access_unbound_in_1: &'static str,
    pub storage_access_unbound_in_2: &'static str,
    pub storage_access_unbound_in_3: &'static str,
    pub storage_replace_native_coordinates_in_1: &'static str,
    pub tasks_policy_agent_versions_in_1: &'static str,
    pub tasks_policy_agent_versions_in_2: &'static str,
    pub tasks_policy_agent_versions_in_3: &'static str,
    pub tasks_policy_agent_versions_in_4: &'static str,
    pub tasks_credential_tasks_authorized_in_1: &'static str,
    pub tasks_worker_pending_in_1: &'static str,
    pub tasks_worker_pending_in_2: &'static str,
    pub tasks_retirement_retire_in_1: &'static str,
    pub tasks_retirement_retire_in_2: &'static str,
    pub tasks_retirement_progress_on_1: &'static str,
    pub tasks_wake_policy_in_1: &'static str,
    pub tasks_policy_recovery_prepare_in_1: &'static str,
    pub tasks_policy_recovery_advance_in_1: &'static str,
    pub tasks_policy_recovery_advance_in_2: &'static str,
    pub tasks_queries_page_on_1: &'static str,
    pub tasks_queries_detail_on_1: &'static str,
    pub tasks_queries_detail_on_2: &'static str,
    pub tasks_queries_assignment_ids_on_1: &'static str,
    pub tasks_actions_recovery_accept_action_dispatch_1: &'static str,
    pub tasks_actions_recovery_accept_action_dispatch_2: &'static str,
    pub tasks_actions_production_accept_for_device_1: &'static str,
    pub tasks_actions_production_queue_run_in_1: &'static str,
    pub tasks_actions_production_policy_pending_in_1: &'static str,
    pub tasks_actions_production_occurrence_available_in_1: &'static str,
    pub tasks_actions_poll_offer_candidates_1: &'static str,
    pub tasks_actions_poll_cancellations_1: &'static str,
    pub tasks_actions_storage_run_in_1: &'static str,
    pub tasks_actions_storage_run_in_2: &'static str,
    pub tasks_actions_storage_save_run_1: &'static str,
    pub tasks_actions_storage_save_run_2: &'static str,
    pub tasks_actions_storage_owned_ids_on_1: &'static str,
    pub tasks_actions_storage_active_count_on_1: &'static str,
    pub tasks_actions_storage_association_on_1: &'static str,
    pub task_relations: &'static str,
    pub object_manifest: &'static str,
    pub access_contract: &'static str,
    pub filevault_material_109: &'static str,
    pub filevault_material_110: &'static str,
    pub filevault_material_111: &'static str,
    pub filevault_material_112: &'static str,
    pub agent_authority_admission: &'static str,
    pub agent_authority_header: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $schema:literal, $schema_decl:literal, $access_schema:literal, $access:literal, $entries:literal, $versions:literal, $agent_guards:literal, $agent_materials:literal, $rss_login_uses:literal, $disclosures:literal, $tasks_runs:literal, $tasks_operations:literal, $tasks_requests:literal, $tasks_receipts:literal, $tasks_policy_recovery:literal, $tasks_agent_admission:literal, $task_schema:literal, $task_schema_decl:literal, $policy_policies:literal, $policy_versions:literal, $policy_assignments:literal, $policy_triggers:literal, $policy_requests:literal, $policy_work:literal, $policy_schedule_scan:literal, $policy_event_batches:literal, $policy_event_members:literal, $scope:literal, $filevault_access_e:literal, $filevault_access_b:literal, $owner:literal, $command_runtime:literal, $policy_runtime:literal, $identity_runtime:literal, $create_mdm_recovery:literal, $create_mdm_recovery_tasks:literal, $role_mdm_inventory_runtime:literal, $role_mdm_scope_runtime:literal, $role_mdm_resource_runtime:literal, $role_mdm_software_runtime:literal, $role_mdm_telemetry_runtime:literal, $save_retired_run:literal, $native_retirement_clear:literal, $index_43:literal, $index_44:literal, $index_45:literal, $index_46:literal, $contract_table_47:literal, $contract_table_48:literal, $contract_table_49:literal, $contract_table_50:literal, $contract_table_51:literal, $contract_table_52:literal, $contract_table_53:literal, $contract_table_54:literal, $contract_table_55:literal, $access_contract_tables:literal, $access_contract_functions:literal, $host_tenant_fk:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                retention_material: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON(v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.id=$2 AND v.version=$3"),
                install: concat!(r###"BEGIN;
"###, $create_mdm_recovery, r###";
REVOKE ALL ON "###, $schema_decl, r###" FROM PUBLIC;
CREATE TABLE "###, $entries, r###" (
 tenant_id uuid NOT NULL"###, $host_tenant_fk, r###", id uuid NOT NULL,
 device text NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 subject jsonb NOT NULL CHECK(octet_length(subject::text)<=2048),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0), current_version bigint,
 retired boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,device,registration,generation,subject),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES "###, $access_schema, r###"registrations(tenant_id,id,generation),
 FOREIGN KEY(tenant_id,device) REFERENCES "###, $access_schema, r###"devices(tenant_id,id)
);
CREATE TABLE "###, $versions, r###" (
 tenant_id uuid NOT NULL, entry uuid NOT NULL, version bigint NOT NULL CHECK(version>0),
 operation uuid NOT NULL, validity text NOT NULL CHECK(validity IN('unverified','verified','unknown','superseded','revoked')),
 key_id text, sealed bytea CHECK(octet_length(sealed)<=8192),
 created_at bigint NOT NULL, invalidated_at bigint,
 pending boolean NOT NULL DEFAULT true,
 cleanup_checked_at bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant_id,entry,version), UNIQUE(tenant_id,entry,operation),
 FOREIGN KEY(tenant_id,entry) REFERENCES "###, $entries, r###"(tenant_id,id),
 CHECK((key_id IS NULL)=(sealed IS NULL)),
 CHECK((validity IN('revoked','superseded'))=(invalidated_at IS NOT NULL))
);
ALTER TABLE "###, $entries, " ADD FOREIGN KEY(tenant_id,id,current_version) REFERENCES ", $versions, r###"(tenant_id,entry,version);
"###, $index_43, " ON ", $versions, r###"(tenant_id,operation);
CREATE TABLE "###, $agent_guards, r###" (
 tenant_id uuid NOT NULL, registration uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0), task uuid NOT NULL, attempt uuid NOT NULL,
 PRIMARY KEY(tenant_id,registration,generation), UNIQUE(tenant_id,task),
 FOREIGN KEY(tenant_id,registration,generation) REFERENCES "###, $access_schema, r###"registrations(tenant_id,id,generation)
);
ALTER TABLE "###, $agent_guards, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $agent_guards, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $agent_guards, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE "###, $agent_materials, r###" (
 tenant_id uuid NOT NULL, task uuid NOT NULL, attempt uuid NOT NULL, entry uuid NOT NULL, version bigint NOT NULL,
 PRIMARY KEY(tenant_id,task,attempt,entry),
 FOREIGN KEY(tenant_id,entry,version) REFERENCES "###, $versions, r###"(tenant_id,entry,version)
);
ALTER TABLE "###, $agent_materials, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $agent_materials, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $agent_materials, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
"###, $index_44, " ON ", $versions, r###"(tenant_id,invalidated_at) WHERE sealed IS NOT NULL AND NOT pending;
ALTER TABLE "###, $entries, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $entries, r###" FORCE ROW LEVEL SECURITY;
ALTER TABLE "###, $versions, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $versions, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $entries, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON "###, $versions, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE "###, $rss_login_uses, r###" (
 tenant_id uuid NOT NULL, operation uuid NOT NULL, entry uuid NOT NULL, version bigint NOT NULL,
 used_at bigint NOT NULL CHECK(used_at>0), received_at bigint NOT NULL CHECK(received_at>0),
 PRIMARY KEY(tenant_id,operation),
 FOREIGN KEY(tenant_id,entry,version) REFERENCES "###, $versions, r###"(tenant_id,entry,version)
);
ALTER TABLE "###, $rss_login_uses, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $rss_login_uses, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $rss_login_uses, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE TABLE "###, $disclosures, r###" (
 tenant_id uuid NOT NULL"###, $host_tenant_fk, r###",actor text NOT NULL,operation uuid NOT NULL,
 device text NOT NULL,entry uuid NOT NULL,version bigint NOT NULL,
 PRIMARY KEY(tenant_id,actor,operation),
 FOREIGN KEY(tenant_id,entry,version) REFERENCES "###, $versions, r###"(tenant_id,entry,version)
);
ALTER TABLE "###, $disclosures, r###" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "###, $disclosures, r###" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON "###, $disclosures, r###" USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT USAGE ON "###, $schema_decl, " TO ", $identity_runtime, r###";
GRANT SELECT ON "###, $entries, ",", $versions, ",", $disclosures, " TO ", $identity_runtime, r###";
GRANT INSERT ON "###, $disclosures, " TO ", $identity_runtime, r###";
GRANT UPDATE(tenant_id) ON "###, $entries, ",", $versions, " TO ", $identity_runtime, r###";
REVOKE ALL ON "###, $entries, ",", $versions, ",", $agent_guards, ",", $agent_materials, ",", $rss_login_uses, ",", $disclosures, r###" FROM PUBLIC;
GRANT USAGE ON "###, $schema_decl, " TO ", $access, ",", $command_runtime, r###";
GRANT SELECT,INSERT ON "###, $entries, ",", $versions, ",", $agent_guards, ",", $agent_materials, ",", $rss_login_uses, " TO ", $access, ",", $command_runtime, r###";
GRANT SELECT ON "###, $disclosures, " TO ", $access, r###";
GRANT UPDATE(revision,current_version,retired) ON "###, $entries, " TO ", $access, ",", $command_runtime, r###";
GRANT UPDATE(validity,key_id,sealed,invalidated_at,pending,cleanup_checked_at) ON "###, $versions, " TO ", $access, ",", $command_runtime, r###";

GRANT DELETE ON "###, $agent_guards, " TO ", $command_runtime, r###";
COMMIT;
"###),
                tasks: concat!(r###"-- Fresh installation: Recovery owns its complete execution state.
BEGIN;

"###, $create_mdm_recovery_tasks, r###";

CREATE TABLE "###, $tasks_runs, r###" (
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
    result jsonb CHECK(result IS NULL OR octet_length(result::text)<=1114112),
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,policy_version,device,occurrence)
);

ALTER TABLE "###, $tasks_runs, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $tasks_runs, r###" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $tasks_runs, r###"
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE "###, $tasks_agent_admission, r###" (
    tenant_id uuid NOT NULL,
    registration uuid NOT NULL,
    policy_after uuid,
    PRIMARY KEY(tenant_id,registration)
);

ALTER TABLE "###, $tasks_agent_admission, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $tasks_agent_admission, r###" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $tasks_agent_admission, r###"
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE TABLE "###, $tasks_policy_recovery, r###" (
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

ALTER TABLE "###, $tasks_policy_recovery, r###" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "###, $tasks_policy_recovery, r###" FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant ON "###, $tasks_policy_recovery, r###"
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

"###, $index_45, " ON ", $tasks_runs, r###"(tenant_id,registration,available_at,id)
 WHERE state->>'execution'='not_started' AND state->>'cancellation'='none';

"###, $index_46, " ON ", $tasks_runs, r###"(tenant_id,policy_version,available_at,id);

COMMIT;"###),
                task_admission: concat!("WITH owned(relation) AS(VALUES('", $tasks_runs, "'),('", $tasks_policy_recovery, r###"'))
SELECT current_user IN('"###, $command_runtime, "','", $policy_runtime, r###"') AND session_user=current_user
 AND current_setting('transaction_isolation')='read committed'
 AND NOT EXISTS(SELECT FROM owned o LEFT JOIN pg_class c ON c.oid=to_regclass(o.relation)
 WHERE c.oid IS NULL OR c.relkind<>'r' OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
 OR NOT has_table_privilege(current_user,c.oid,'SELECT,INSERT') OR has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND has_column_privilege(current_user,'"###, $tasks_runs, "','state','UPDATE') AND has_column_privilege(current_user,'", $tasks_runs, r###"','result','UPDATE')
 AND has_column_privilege(current_user,'"###, $tasks_policy_recovery, r###"','input_revision','UPDATE')
"###),
                service_disclose_inner_1: concat!("INSERT INTO ", $disclosures, "(tenant_id,actor,operation,device,entry,version) VALUES($1::uuid,$2,$3,$4,$5,$6)"),
                service_revoke_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1::uuid AND ((e.subject->>'kind'<>'filevault' AND e.device=$2) OR ", $filevault_access_e, ") AND e.id=$3 AND v.version=$4"),
                service_revoke_2: concat!("UPDATE ", $versions, " SET validity='revoked',invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND entry=$2 AND version=$3"),
                service_revoke_3: concat!("UPDATE ", $entries, " SET current_version=NULL WHERE tenant_id=$1::uuid AND id=$2 AND current_version=$3"),
                service_revoke_4: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1::uuid AND e.id=$2 AND v.version=$3"),
                service_read_locked_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1::uuid AND ((e.subject->>'kind'<>'filevault' AND e.device=$2) OR ", $filevault_access_e, ") AND e.id=$3 AND v.version=$4 AND NOT e.retired"),
                service_read_locked_2: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1::uuid AND ((e.subject->>'kind'<>'filevault' AND e.device=$2) OR ", $filevault_access_e, ") AND e.id=$3 AND v.version=$4 AND NOT e.retired FOR UPDATE OF e,v"),
                service_disclosure_receipt_1: concat!("SELECT device,entry,version FROM ", $disclosures, " WHERE tenant_id=$1::uuid AND actor=$2 AND operation=$3"),
                directory_read_1: concat!("SELECT jsonb_build_object('id',e.id,'binding',jsonb_build_object('device',e.device,'registration',e.registration,'generation',e.generation,'subject',e.subject),'version',v.version,'current',coalesce(e.current_version=v.version,false),'validity',v.validity,'escrowed',v.sealed IS NOT NULL,'operation',v.operation,'createdAt',v.created_at,'invalidatedAt',v.invalidated_at) FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id="),
                directory_read_2: concat!(") OR ", $schema, "filevault_accessible(e.subject,"),
                storage_rss_use_in_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.id=$2 AND v.version=$3 FOR UPDATE OF e"),
                storage_rss_use_in_2: concat!("SELECT entry,version,used_at FROM ", $rss_login_uses, " WHERE tenant_id=$1 AND operation=$2"),
                storage_rss_use_in_3: concat!("SELECT count(*) FROM ", $rss_login_uses, " WHERE tenant_id=$1 AND entry=$2"),
                storage_rss_use_in_4: concat!("INSERT INTO ", $rss_login_uses, "(tenant_id,operation,entry,version,used_at,received_at) VALUES($1,$2,$3,$4,$5,$6)"),
                storage_reserve_in_1: concat!("INSERT INTO ", $entries, "(tenant_id,id,device,registration,generation,subject) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,device,registration,generation,subject) DO NOTHING"),
                storage_reserve_in_2: concat!("SELECT id,revision,retired FROM ", $entries, " WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND subject=$5 FOR UPDATE"),
                storage_reserve_in_3: concat!("SELECT version FROM ", $versions, " WHERE tenant_id=$1 AND entry=$2 AND operation=$3"),
                storage_reserve_in_4: concat!("SELECT count(*) FROM ", $versions, " WHERE tenant_id=$1 AND entry=$2"),
                storage_reserve_in_5: concat!("SELECT EXISTS(SELECT 1 FROM ", $versions, " WHERE tenant_id=$1 AND entry=$2 AND pending)"),
                storage_reserve_in_6: concat!("INSERT INTO ", $versions, "(tenant_id,entry,version,operation,validity,created_at) VALUES($1,$2,$3,$4,'unverified',floor(extract(epoch FROM clock_timestamp()))::bigint)"),
                storage_reserve_in_7: concat!("UPDATE ", $entries, " SET revision=$3 WHERE tenant_id=$1 AND id=$2"),
                storage_ingest_in_1: concat!("UPDATE ", $versions, " SET key_id=$4,sealed=$5 WHERE tenant_id=$1 AND entry=$2 AND version=$3"),
                storage_locked_version_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.id=$2 AND v.version=$3 AND NOT e.retired FOR UPDATE OF e,v"),
                storage_verify_in_1: concat!("SELECT revision FROM ", $entries, " WHERE tenant_id=$1 AND id=$2"),
                storage_verify_in_2: concat!("UPDATE ", $versions, " SET validity='superseded',pending=false,invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1 AND entry=$2 AND version<>$3 AND invalidated_at IS NULL"),
                storage_verify_in_3: concat!("UPDATE ", $versions, " SET validity='verified',pending=false WHERE tenant_id=$1 AND entry=$2 AND version=$3"),
                storage_verify_in_4: concat!("UPDATE ", $entries, " SET current_version=$3 WHERE tenant_id=$1 AND id=$2"),
                storage_unknown_in_1: concat!("UPDATE ", $versions, " SET validity='unknown' WHERE tenant_id=$1 AND invalidated_at IS NULL AND entry IN(SELECT entry FROM ", $versions, " WHERE tenant_id=$1 AND operation=$2)"),
                storage_retire_in_1: concat!("UPDATE ", $entries, " SET retired=true WHERE tenant_id=$1::uuid AND registration=$2 AND subject->>'kind'<>'filevault'"),
                storage_retire_in_2: concat!("UPDATE ", $versions, " v SET validity='revoked',invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) FROM ", $entries, " e WHERE (v.tenant_id,v.entry)=(e.tenant_id,e.id) AND e.tenant_id=$1::uuid AND e.registration=$2 AND e.subject->>'kind'<>'filevault'"),
                storage_native_action_in_1: concat!("SELECT action,coordinates,recipient,reconciles FROM ", $schema, "native_actions WHERE tenant_id=$1 AND operation=$2 AND device=$3 AND registration=$4 AND generation=$5"),
                storage_link_native_in_1: concat!("INSERT INTO ", $schema, "native_actions(tenant_id,operation,device,registration,generation,action,coordinates,recipient,reconciles) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)"),
                storage_coordinates_in_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.device=$2 AND e.id=$3 AND v.version=$4 AND NOT e.retired"),
                storage_settled_in_1: concat!("UPDATE ", $versions, " SET pending=false WHERE tenant_id=$1 AND entry=$2 AND version=$3"),
                storage_validate_keys_in_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND (v.entry,v.version) IN(SELECT DISTINCT ON(key_id) entry,version FROM ", $versions, " WHERE tenant_id=$1 AND sealed IS NOT NULL ORDER BY key_id,entry,version)"),
                storage_prepare_rewrap_in_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND v.sealed IS NOT NULL AND v.key_id<>$2 ORDER BY e.id,v.version LIMIT 100 FOR UPDATE OF v"),
                storage_rewrap_in_1: concat!("UPDATE ", $versions, " SET key_id=$4,sealed=$5 WHERE tenant_id=$1 AND entry=$2 AND version=$3"),
                storage_expired_in_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND NOT v.pending AND NOT EXISTS(SELECT 1 FROM ", $agent_guards, " g WHERE g.tenant_id=e.tenant_id AND g.registration=e.registration AND g.generation=e.generation) AND NOT EXISTS(SELECT 1 FROM ", $entries, " held JOIN ", $versions, " unresolved ON(unresolved.tenant_id,unresolved.entry)=(held.tenant_id,held.id) WHERE held.tenant_id=e.tenant_id AND held.registration=e.registration AND unresolved.pending) AND v.sealed IS NOT NULL AND v.invalidated_at<=floor(extract(epoch FROM clock_timestamp()))::bigint-7776000 ORDER BY v.cleanup_checked_at,v.invalidated_at,e.id,v.version LIMIT 100"),
                storage_clear_expired_in_1: concat!("UPDATE ", $versions, " v SET sealed=NULL,key_id=NULL FROM ", $entries, " e WHERE (e.tenant_id,e.id)=(v.tenant_id,v.entry) AND v.tenant_id=$1 AND v.entry=$2 AND v.version=$3 AND NOT v.pending AND v.invalidated_at<=floor(extract(epoch FROM clock_timestamp()))::bigint-7776000 AND NOT EXISTS(SELECT 1 FROM ", $agent_guards, " g WHERE g.tenant_id=e.tenant_id AND g.registration=e.registration AND g.generation=e.generation) AND NOT EXISTS(SELECT 1 FROM ", $entries, " held JOIN ", $versions, " unresolved ON(unresolved.tenant_id,unresolved.entry)=(held.tenant_id,held.id) WHERE held.tenant_id=e.tenant_id AND held.registration=e.registration AND unresolved.pending)"),
                storage_verify_existing_secret_in_1: concat!("SELECT id FROM ", $entries, " WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND subject=$5 AND revision=$6 AND NOT retired FOR UPDATE"),
                storage_link_agent_in_1: concat!("INSERT INTO ", $agent_materials, "(tenant_id,task,attempt,entry,version) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING"),
                storage_link_agent_in_2: concat!("SELECT version FROM ", $agent_materials, " WHERE tenant_id=$1 AND task=$2 AND attempt=$3 AND entry=$4"),
                storage_agent_materials_in_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) JOIN ", $agent_materials, " a ON(a.tenant_id,a.entry,a.version)=(v.tenant_id,v.entry,v.version) WHERE e.tenant_id=$1 AND a.task=$2 AND a.attempt=$3 ORDER BY e.id LIMIT 513"),
                storage_supersede_in_1: concat!("SELECT id,revision FROM ", $entries, " WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND subject=$5 FOR UPDATE"),
                storage_supersede_in_2: concat!("UPDATE ", $versions, " SET validity='superseded',pending=false,invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1 AND entry=$2 AND invalidated_at IS NULL"),
                storage_supersede_in_3: concat!("UPDATE ", $entries, " SET current_version=NULL WHERE tenant_id=$1 AND id=$2"),
                storage_start_agent_in_1: concat!("INSERT INTO ", $agent_guards, "(tenant_id,registration,task,attempt,generation) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING"),
                storage_start_agent_in_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $agent_guards, " WHERE tenant_id=$1 AND registration=$2 AND task=$3 AND attempt=$4 AND generation=$5)"),
                storage_finish_agent_in_1: concat!("DELETE FROM ", $agent_guards, " WHERE tenant_id=$1 AND task=$2 RETURNING attempt"),
                storage_cleared_in_1: concat!("SELECT revision FROM ", $entries, " WHERE tenant_id=$1 AND id=$2"),
                storage_cleared_in_2: concat!("UPDATE ", $versions, " SET validity='revoked',pending=false,invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1 AND entry=$2 AND (invalidated_at IS NULL OR pending)"),
                storage_cleared_in_3: concat!("UPDATE ", $entries, " SET current_version=NULL WHERE tenant_id=$1 AND id=$2"),
                storage_revisions_in_1: concat!("SELECT subject,revision FROM ", $entries, " WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND NOT retired ORDER BY id LIMIT 513"),
                storage_uncertain_version_in_1: concat!("UPDATE ", $versions, " SET validity='unknown' WHERE tenant_id=$1 AND entry=$2 AND version=$3 AND invalidated_at IS NULL"),
                storage_input_copies_in_1: concat!("SELECT operation FROM ", $schema, "native_actions WHERE tenant_id=$1 AND registration=$2 AND NOT inputs_purged ORDER BY operation LIMIT 100"),
                storage_input_purged_in_1: concat!("UPDATE ", $schema, "native_actions SET inputs_purged=true WHERE tenant_id=$1 AND operation=$2"),
                storage_inputs_remain_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $schema, "native_actions WHERE tenant_id=$1 AND registration=$2 AND NOT inputs_purged)"),
                storage_agent_guard_in_1: concat!("SELECT task,attempt FROM ", $agent_guards, " WHERE tenant_id=$1 AND registration=$2 AND generation=$3"),
                storage_reconcile_in_1: concat!("SELECT v.operation FROM ", $versions, " v JOIN ", $entries, " e ON(e.tenant_id,e.id,e.revision)=(v.tenant_id,v.entry,v.version) WHERE e.tenant_id=$1 AND e.id=$2 AND v.pending"),
                storage_reconcile_in_2: concat!("UPDATE ", $versions, " SET validity='superseded',pending=false,invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1 AND entry=$2 AND version<>$3 AND invalidated_at IS NULL"),
                storage_reconcile_in_3: concat!("UPDATE ", $versions, " SET validity='verified',pending=false WHERE tenant_id=$1 AND entry=$2 AND version=$3"),
                storage_reconcile_in_4: concat!("UPDATE ", $entries, " SET current_version=$3 WHERE tenant_id=$1 AND id=$2"),
                storage_recovery_secret_in_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.device=$2 AND e.registration=$3 AND e.generation=$4 AND e.subject=$5 AND NOT e.retired AND v.invalidated_at IS NULL ORDER BY v.version DESC FOR UPDATE OF e,v"),
                storage_cleanup_visited_in_1: concat!("UPDATE ", $versions, " SET cleanup_checked_at=(extract(epoch FROM clock_timestamp())*1000000)::bigint WHERE tenant_id=$1 AND entry=$2 AND version=$3"),
                storage_current_in_1: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.device=$2 AND e.registration=$3 AND e.generation=$4 AND e.subject=$5 AND e.current_version=v.version AND NOT e.retired FOR UPDATE OF e,v"),
                storage_access_unbound_in_1: concat!("SELECT id FROM ", $entries, " WHERE tenant_id=$1 AND device=$2 AND registration=$3 AND generation=$4 AND subject->>'kind'='rss_login' AND subject->>'binding'=$5 AND (subject->>'bindingGeneration')::bigint<$6 ORDER BY id FOR UPDATE"),
                storage_access_unbound_in_2: concat!("UPDATE ", $versions, " SET validity='revoked',invalidated_at=coalesce(invalidated_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1 AND entry=$2 AND NOT pending"),
                storage_access_unbound_in_3: concat!("UPDATE ", $entries, " SET current_version=NULL WHERE tenant_id=$1 AND id=$2 AND NOT EXISTS(SELECT 1 FROM ", $versions, " WHERE tenant_id=$1 AND entry=$2 AND pending)"),
                storage_replace_native_coordinates_in_1: concat!("UPDATE ", $schema, "native_actions SET coordinates=$3 WHERE tenant_id=$1 AND operation=$2 AND action IN('collect_filevault','rotate_filevault')"),
                tasks_policy_agent_versions_in_1: concat!("INSERT INTO ", $tasks_agent_admission, "(tenant_id,registration) VALUES($1::uuid,$2::uuid) ON CONFLICT DO NOTHING"),
                tasks_policy_agent_versions_in_2: concat!("SELECT policy_after FROM ", $tasks_agent_admission, " WHERE tenant_id=$1::uuid AND registration=$2::uuid FOR UPDATE"),
                tasks_policy_agent_versions_in_3: concat!("SELECT id,current_version FROM ", $policy_policies, " WHERE tenant_id=$1::uuid AND (state='enabled') AND definition->'action'->>'kind' =ANY($3) AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 64"),
                tasks_policy_agent_versions_in_4: concat!("UPDATE ", $tasks_agent_admission, " SET policy_after=$3 WHERE tenant_id=$1::uuid AND registration=$2::uuid"),
                tasks_credential_tasks_authorized_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $policy_policies, " WHERE tenant_id=$1 AND id=$2 AND state='enabled')"),
                tasks_worker_pending_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $tasks_policy_recovery, " WHERE tenant_id=$1::uuid AND policy=$2 AND input_revision>input_consumed)"),
                tasks_worker_pending_in_2: concat!("SELECT EXISTS(SELECT 1 FROM ", $tasks_runs, " t WHERE tenant_id=$1::uuid AND id=$2 AND (state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed'))"),
                tasks_retirement_retire_in_1: concat!("SELECT id,state AS state FROM ", $tasks_runs, " a WHERE tenant_id=$1::uuid AND registration=$2 AND id>$3 AND ((state->>'execution' IN ('not_started','running','waiting_reboot','unknown') AND state->>'cancellation'='none')) AND EXISTS(SELECT 1 FROM ", $access_schema, "registrations r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.registration) AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM ", $access_schema, "devices d WHERE (d.tenant_id,d.id)=(r.tenant_id,r.device) AND d.retirement IS NOT NULL) AND ", $native_retirement_clear, "))) ORDER BY id LIMIT 64"),
                tasks_retirement_retire_in_2: concat!("SELECT ", $save_retired_run, "($1,$2,$3,$4)"),
                tasks_retirement_progress_on_1: concat!("SELECT count(*)>0,(array_agg(t.id ORDER BY t.id) FILTER(WHERE t.state->>'execution'='unknown'))[1] FROM ", $tasks_runs, " t WHERE t.tenant_id=$1::uuid AND t.registration=ANY($2) AND (t.state->>'execution' IN('running','waiting_reboot','unknown'))"),
                tasks_wake_policy_in_1: concat!("INSERT INTO ", $tasks_policy_recovery, "(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,policy) DO UPDATE SET input_revision=", $tasks_policy_recovery, ".input_revision+1"),
                tasks_policy_recovery_prepare_in_1: concat!("SELECT * FROM ", $tasks_policy_recovery, " WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE"),
                tasks_policy_recovery_advance_in_1: concat!("SELECT r.id FROM ", $tasks_runs, " r JOIN ", $policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::uuid IS NULL OR r.id>$3) ORDER BY r.id LIMIT 33"),
                tasks_policy_recovery_advance_in_2: concat!("UPDATE ", $tasks_policy_recovery, " SET input_consumed=$3,input_window=$4,recovery_after=$5,runs_done=$6 WHERE tenant_id=$1::uuid AND policy=$2"),
                tasks_queries_page_on_1: concat!(",'result',r.result) FROM ", $tasks_runs, " r JOIN ", $policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::bigint IS NULL OR (r.available_at,r.id)<($3,$4)) ORDER BY r.available_at DESC,r.id DESC LIMIT $5"),
                tasks_queries_detail_on_1: concat!("SELECT r.device FROM ", $tasks_runs, " r JOIN ", $policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3"),
                tasks_queries_detail_on_2: concat!(",'result',r.result) FROM ", $tasks_runs, " r JOIN ", $policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.id=$3"),
                tasks_queries_assignment_ids_on_1: concat!("SELECT r.id FROM ", $tasks_runs, " r JOIN ", $policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND r.device=$3 AND $6='agent' AND r.registration=$4 AND r.generation=$5 ORDER BY r.id"),
                tasks_actions_recovery_accept_action_dispatch_1: concat!("SELECT gateway_accepted FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2::uuid AND dispatch_fingerprint=$3 FOR UPDATE"),
                tasks_actions_recovery_accept_action_dispatch_2: concat!("UPDATE ", $tasks_runs, " SET gateway_accepted=true WHERE tenant_id=$1::uuid AND id=$2::uuid"),
                tasks_actions_production_accept_for_device_1: concat!("SELECT t.id,t.created_at,t.deadline FROM ", $policy_triggers, " t WHERE t.tenant_id=$1::uuid AND t.version=$2 AND t.deadline>$4 AND $5 AND NOT EXISTS(SELECT 1 FROM ", $tasks_runs, " r WHERE r.tenant_id=t.tenant_id AND r.policy_version=t.version AND r.device=$3 AND r.occurrence='explicit:'||t.id::text) ORDER BY t.created_at,t.id LIMIT 1"),
                tasks_actions_production_queue_run_in_1: concat!("INSERT INTO ", $tasks_runs, "(tenant_id,id,policy_version,device,registration,generation,occurrence,available_at,deadline,state,dispatch_fingerprint,created_at,source_objects,origin) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)"),
                tasks_actions_production_policy_pending_in_1: concat!("SELECT coalesce(bool_or(state->>'execution'='unknown' OR ((state->>'execution'='running' OR (state->>'execution'='not_started' AND deadline>$4)) AND state->>'cancellation'<>'confirmed')),false),max(created_at) FILTER(WHERE policy_version=$6) FROM ", $tasks_runs, " r JOIN ", $policy_versions, " v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2::uuid AND device=$3 AND (registration=$5::uuid OR state->>'execution'='unknown')"),
                tasks_actions_production_occurrence_available_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND policy_version=$2::uuid AND device=$3 AND occurrence=$4)"),
                tasks_actions_poll_offer_candidates_1: concat!("SELECT id,available_at FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND registration=$2 AND state->>'execution'='not_started' AND state->>'cancellation'='none' AND gateway_accepted AND available_at<=$3 AND deadline>$3 AND (state->'delivery'->>'kind'='queued' OR (state->'delivery'->>'leaseUntil')::bigint<=$3) AND ($4::bigint IS NULL OR (available_at,id)>($4,$5::uuid)) ORDER BY available_at,id LIMIT 128"),
                tasks_actions_poll_cancellations_1: concat!("SELECT id,state->'delivery'->>'attempt' AS attempt FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND registration=$2 AND state->>'cancellation'='requested' AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4"),
                tasks_actions_storage_run_in_1: concat!("SELECT id FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                tasks_actions_storage_run_in_2: concat!("SELECT * FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2"),
                tasks_actions_storage_save_run_1: concat!("SELECT state FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2"),
                tasks_actions_storage_save_run_2: concat!("UPDATE ", $tasks_runs, " SET state=$3,result=$4 WHERE tenant_id=$1::uuid AND id=$2 AND (state IS DISTINCT FROM $3 OR result IS DISTINCT FROM $4)"),
                tasks_actions_storage_owned_ids_on_1: concat!("SELECT id FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND id=ANY($2)"),
                tasks_actions_storage_active_count_on_1: concat!("SELECT count(*) FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND device=$2 AND state->>'execution' IN('not_started','running','unknown','waiting_reboot') AND (deadline>$3 OR state->>'startedAt' IS NOT NULL) AND state->>'cancellation'<>'confirmed'"),
                tasks_actions_storage_association_on_1: concat!("SELECT device,NULL::uuid FROM ", $tasks_runs, " WHERE tenant_id=$1::uuid AND id=$2"),
                task_relations: concat!(r###"BEGIN;
SET LOCAL check_function_bodies=false;

ALTER TABLE "###, $tasks_runs, " ADD FOREIGN KEY(tenant_id,policy_version) REFERENCES ", $policy_versions, r###"(tenant_id,id);

ALTER TABLE "###, $tasks_runs, " ADD FOREIGN KEY(tenant_id,device) REFERENCES ", $access_schema, r###"devices(tenant_id,id);

ALTER TABLE "###, $tasks_runs, " ADD FOREIGN KEY(tenant_id,registration) REFERENCES ", $access_schema, r###"registrations(tenant_id,id);

ALTER TABLE "###, $tasks_agent_admission, " ADD FOREIGN KEY(tenant_id,registration) REFERENCES ", $access_schema, r###"registrations(tenant_id,id);

ALTER TABLE "###, $tasks_policy_recovery, " ADD FOREIGN KEY(tenant_id,policy) REFERENCES ", $policy_policies, r###"(tenant_id,id);

GRANT USAGE ON "###, $task_schema_decl, " TO ", $command_runtime, ",", $policy_runtime, ",", $access, r###";

GRANT SELECT,INSERT ON "###, $tasks_runs, ",", $tasks_policy_recovery, " TO ", $command_runtime, ",", $policy_runtime, r###";

GRANT UPDATE(state,result,source_objects) ON "###, $tasks_runs, " TO ", $command_runtime, ",", $policy_runtime, r###";

GRANT UPDATE(gateway_accepted) ON "###, $tasks_runs, " TO ", $command_runtime, r###";

GRANT UPDATE(policy_after) ON "###, $tasks_agent_admission, " TO ", $command_runtime, r###";

GRANT UPDATE(input_revision,input_consumed,input_window,recovery_after,runs_done) ON "###, $tasks_policy_recovery, " TO ", $command_runtime, r###";

GRANT UPDATE(input_revision) ON "###, $tasks_policy_recovery, " TO ", $policy_runtime, r###";

CREATE FUNCTION "###, $save_retired_run, r###"(p_registration uuid,p_run uuid,p_previous jsonb,p_state jsonb) RETURNS boolean
 LANGUAGE sql SECURITY DEFINER SET search_path TO 'pg_catalog'
 AS $$
 WITH changed AS (
 UPDATE "###, $tasks_runs, r###" a SET state=p_state
 WHERE a.tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND a.registration=p_registration AND a.id=p_run AND a.state=p_previous
 AND a.state->>'execution' IN ('not_started','running','waiting_reboot','unknown')
 AND a.state->>'cancellation'='none'
 AND p_state=jsonb_set(p_previous,'{cancellation}',to_jsonb(CASE WHEN p_previous->>'execution'='not_started' THEN 'confirmed'::text ELSE 'requested'::text END))
 AND EXISTS(SELECT 1 FROM "###, $access_schema, "registrations r WHERE (r.tenant_id,r.id)=(a.tenant_id,a.registration) AND (r.state<>'active' OR (EXISTS(SELECT 1 FROM ", $access_schema, "devices d WHERE (d.tenant_id,d.id)=(r.tenant_id,r.device) AND d.retirement IS NOT NULL) AND ", $native_retirement_clear, r###")))
 RETURNING a.id
 ) SELECT EXISTS(SELECT 1 FROM changed);
$$;

REVOKE ALL ON FUNCTION "###, $save_retired_run, r###"(uuid,uuid,jsonb,jsonb) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION "###, $save_retired_run, "(uuid,uuid,jsonb,jsonb) TO ", $access, ",", $command_runtime, r###";
GRANT SELECT ON "###, $tasks_runs, " TO ", $access, r###";
GRANT SELECT,INSERT ON "###, $tasks_agent_admission, " TO ", $command_runtime, r###";
COMMIT;"###),
                object_manifest: concat!(r###"{"tables":[""###, $agent_guards, r###"",""###, $agent_materials, r###"",""###, $disclosures, r###"",""###, $entries, r###"",""###, $rss_login_uses, r###"",""###, $versions, r###"",""###, $tasks_agent_admission, r###"",""###, $tasks_policy_recovery, r###"",""###, $tasks_runs, r###""],"functions":[""###, $save_retired_run, r###""],"views":[]}"###),
                access_contract: concat!(r###"{"tables":[{"###, $contract_table_47, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_48, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_49, r###","read_write":true,"updates":["revision","current_version","retired"],"delete_policy":null},{"###, $contract_table_50, r###","read_write":true,"updates":["validity","key_id","sealed","invalidated_at","pending","cleanup_checked_at"],"delete_policy":null},{"###, $contract_table_51, r###","read_write":true,"updates":[],"delete_policy":null},{"###, $contract_table_52, r###","read_write":false,"read_only":true,"updates":[],"delete_policy":null},{"###, $contract_table_53, r###","read_write":false,"updates":[],"delete_policy":null,"read_only":true},{"###, $contract_table_54, r###","read_write":false,"updates":[],"delete_policy":null},{"###, $contract_table_55, r###","read_write":false,"updates":[],"delete_policy":null}"###, $access_contract_tables, r###"],"functions":[{"name":""###, $save_retired_run, r###"","search_path":"search_path=pg_catalog"}"###, $access_contract_functions, r###"],"external_relations":[],"verified_schemas":[]}"###),
                filevault_material_109: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.subject=$2 AND e.id=$3 AND v.version=$4 AND NOT e.retired"),
                filevault_material_110: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.subject=$2 AND NOT e.retired ORDER BY v.version FOR UPDATE OF e,v"),
                filevault_material_111: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.subject=$2 AND NOT e.retired ORDER BY v.version FOR UPDATE OF e,v"),
                filevault_material_112: concat!("SELECT e.current_version,e.id,e.device,e.registration,e.generation,e.subject,v.version,v.validity,v.operation,v.created_at,v.invalidated_at,v.key_id,v.sealed,v.pending FROM ", $entries, " e JOIN ", $versions, " v ON (v.tenant_id,v.entry)=(e.tenant_id,e.id) WHERE e.tenant_id=$1 AND e.subject=$2 AND NOT e.retired AND v.invalidated_at IS NOT NULL AND v.sealed IS NOT NULL"),
                agent_authority_admission: concat!(r###"WITH expected(signature,language,result,definer,returns_set,volatility,names,config,body,roles) AS (VALUES
('"###, $save_retired_run, "(uuid,uuid,jsonb,jsonb)','sql','boolean',true,false,'v',ARRAY['p_registration','p_run','p_previous','p_state']::text[],ARRAY['search_path=pg_catalog']::text[],$1::text,ARRAY['", $access, "','", $command_runtime, "','", $owner, r###"']::text[])
)
SELECT e.signature FROM expected e
LEFT JOIN pg_proc p ON p.oid=to_regprocedure(e.signature)
LEFT JOIN pg_language l ON l.oid=p.prolang
LEFT JOIN pg_roles r ON r.oid=p.proowner
WHERE p.oid IS NULL OR l.lanname<>e.language OR p.prorettype<>to_regtype(e.result)
 OR p.prokind<>'f' OR p.prosecdef<>e.definer OR p.proretset<>e.returns_set
 OR p.proisstrict OR p.proparallel<>'u'
 OR p.provolatile::text<>e.volatility OR p.proleakproof OR p.prosrc<>e.body
 OR coalesce(p.proargnames,ARRAY[]::text[]) IS DISTINCT FROM e.names OR p.proconfig IS DISTINCT FROM e.config
 OR r.rolname<>'"###, $owner, r###"' OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
 OR pg_has_role(current_user,r.oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
 WHERE a.grantee=0 OR (a.grantee<>p.proowner AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT pg_get_userbyid(a.grantee)=ANY(e.roles))))
 OR EXISTS(SELECT FROM unnest(e.roles) role WHERE NOT has_function_privilege(role,p.oid,'EXECUTE'))
ORDER BY e.signature LIMIT 1
"###),
                agent_authority_header: concat!("CREATE FUNCTION ", $save_retired_run, "("),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_recovery.",
    "SCHEMA mdm_recovery",
    "mdm_access.",
    "mdm_access",
    "mdm_recovery.entries",
    "mdm_recovery.versions",
    "mdm_recovery.agent_guards",
    "mdm_recovery.agent_materials",
    "mdm_recovery.rss_login_uses",
    "mdm_recovery.disclosures",
    "mdm_recovery_tasks.runs",
    "mdm_recovery_tasks.operations",
    "mdm_recovery_tasks.requests",
    "mdm_recovery_tasks.receipts",
    "mdm_recovery_tasks.policy_recovery",
    "mdm_recovery_tasks.agent_admission",
    "mdm_recovery_tasks.",
    "SCHEMA mdm_recovery_tasks",
    "mdm_policy.policies",
    "mdm_policy.versions",
    "mdm_policy.assignments",
    "mdm_policy.triggers",
    "mdm_policy.requests",
    "mdm_policy.work",
    "mdm_policy.schedule_scan",
    "mdm_policy.event_batches",
    "mdm_policy.event_members",
    "mdm_scope.",
    "mdm_recovery.filevault_accessible(e.subject,$2)",
    "mdm_recovery.filevault_accessible(e.subject,$4)",
    "mdm_owner",
    "mdm_command_runtime",
    "mdm_policy_runtime",
    "mdm_identity_runtime",
    "CREATE SCHEMA IF NOT EXISTS mdm_recovery",
    "CREATE SCHEMA IF NOT EXISTS mdm_recovery_tasks",
    "mdm_inventory_runtime",
    "mdm_scope_runtime",
    "mdm_resource_runtime",
    "mdm_software_runtime",
    "mdm_telemetry_runtime",
    "mdm_recovery_tasks.save_retired_run",
    "NOT EXISTS(SELECT 1 FROM mdm_devices.retirement_work w WHERE (w.tenant_id,w.execution)=(a.tenant_id,a.id))",
    "CREATE INDEX recovery_operation",
    "CREATE INDEX recovery_cleanup",
    "CREATE INDEX credential_offer",
    "CREATE INDEX credential_history",
    r###""schema":"mdm_recovery","table":"agent_guards""###,
    r###""schema":"mdm_recovery","table":"agent_materials""###,
    r###""schema":"mdm_recovery","table":"entries""###,
    r###""schema":"mdm_recovery","table":"versions""###,
    r###""schema":"mdm_recovery","table":"rss_login_uses""###,
    r###""schema":"mdm_recovery","table":"disclosures""###,
    r###""schema":"mdm_recovery_tasks","table":"runs""###,
    r###""schema":"mdm_recovery_tasks","table":"agent_admission""###,
    r###""schema":"mdm_recovery_tasks","table":"policy_recovery""###,
    r###",{"schema":"mdm_recovery","table":"native_actions","read_write":true,"updates":[],"delete_policy":null},{"schema":"mdm_recovery","table":"filevault_custodies","read_write":true,"updates":["active","revision","enabled","recipient"],"delete_policy":null},{"schema":"mdm_recovery","table":"filevault_sources","read_write":true,"updates":["custody","epoch","active","association","association_version"],"delete_policy":null},{"schema":"mdm_recovery","table":"filevault_receipts","read_write":true,"updates":[],"delete_policy":null},{"schema":"mdm_recovery_tasks","table":"operations","read_write":false,"updates":[],"delete_policy":null,"read_only":true},{"schema":"mdm_recovery_tasks","table":"requests","read_write":false,"updates":[],"delete_policy":null},{"schema":"mdm_recovery_tasks","table":"device_recovery","read_write":false,"updates":[],"delete_policy":null}"###,
    r###",{"name":"mdm_recovery.filevault_accessible","search_path":"search_path=pg_catalog"},{"name":"mdm_recovery_tasks.native_status","search_path":"search_path=pg_catalog"},{"name":"mdm_recovery_tasks.retirement_commands","search_path":"search_path=pg_catalog"},{"name":"mdm_recovery_tasks.save_retired_command","search_path":"search_path=pg_catalog"},{"name":"mdm_recovery_tasks.recovery_key","search_path":"search_path=pg_catalog","security_definer":false}"###,
    " REFERENCES public.mdm_tenants(tenant_id)"
);
define_storage!(
    da,
    "rss_da.",
    "SCHEMA rss_da",
    "rss_da.",
    "da_access",
    "rss_da.recovery_entries",
    "rss_da.recovery_versions",
    "rss_da.recovery_agent_guards",
    "rss_da.recovery_agent_materials",
    "rss_da.recovery_rss_login_uses",
    "rss_da.recovery_disclosures",
    "rss_da.credential_runs",
    "rss_da.credential_operations",
    "rss_da.credential_requests",
    "rss_da.credential_receipts",
    "rss_da.credential_policy_recovery",
    "rss_da.credential_agent_admission",
    "rss_da.",
    "SCHEMA rss_da",
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
    "false",
    "false",
    "da_owner",
    "da_command_runtime",
    "da_policy_runtime",
    "da_identity_runtime",
    "CREATE SCHEMA IF NOT EXISTS rss_da",
    "CREATE SCHEMA IF NOT EXISTS rss_da",
    "da_inventory_runtime",
    "da_scope_runtime",
    "da_resource_runtime",
    "da_software_runtime",
    "da_telemetry_runtime",
    "rss_da.credential_save_retired_run",
    "true",
    "CREATE INDEX recovery_recovery_operation",
    "CREATE INDEX recovery_recovery_cleanup",
    "CREATE INDEX recovery_credential_offer",
    "CREATE INDEX recovery_credential_history",
    r###""schema":"rss_da","table":"recovery_agent_guards""###,
    r###""schema":"rss_da","table":"recovery_agent_materials""###,
    r###""schema":"rss_da","table":"recovery_entries""###,
    r###""schema":"rss_da","table":"recovery_versions""###,
    r###""schema":"rss_da","table":"recovery_rss_login_uses""###,
    r###""schema":"rss_da","table":"recovery_disclosures""###,
    r###""schema":"rss_da","table":"credential_runs""###,
    r###""schema":"rss_da","table":"credential_agent_admission""###,
    r###""schema":"rss_da","table":"credential_policy_recovery""###,
    "",
    "",
    ""
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
