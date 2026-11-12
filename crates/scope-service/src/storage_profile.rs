//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub calculation_advance_in_1: &'static str,
    pub results_published_on_1: &'static str,
    pub results_source_rows_on_1: &'static str,
    pub results_historical_on_1: &'static str,
    pub results_source_devices_on_1: &'static str,
    pub results_source_objects_on_1: &'static str,
    pub projection_advance_1: &'static str,
    pub projection_advance_2: &'static str,
    pub projection_stage_1: &'static str,
    pub projection_stage_2: &'static str,
    pub projection_stage_3: &'static str,
    pub projection_project_1: &'static str,
    pub projection_project_2: &'static str,
    pub projection_project_3: &'static str,
    pub projection_project_4: &'static str,
    pub projection_project_5: &'static str,
    pub projection_publish_1: &'static str,
    pub projection_publish_2: &'static str,
    pub projection_result_devices_on_1: &'static str,
    pub pages_scope_page_on_1: &'static str,
    pub channels_targets_channel_state_on_1: &'static str,
    pub channels_targets_published_admission_1: &'static str,
    pub channels_reader_rollout_input_on_1: &'static str,
    pub channels_reader_rollout_devices_on_1: &'static str,
    pub channels_query_coordinate: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $policy_schema:literal, $scope_schema:literal, $access_schema:literal, $access_role:literal, $policy_versions:literal, $policy_assignments:literal, $policy_triggers:literal, $policy_requests:literal, $policy_work:literal, $policy_schedule_scan:literal, $policy_event_batches:literal, $policy_event_members:literal, $scope_tasks:literal, $scope_asset_dispatch:literal, $scope_group_changes:literal, $owner:literal, $policy_runtime:literal, $scope_runtime:literal, $command_runtime:literal, $inventory_runtime:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                calculation_advance_in_1: "WITH input_cut AS MATERIALIZED(SELECT * FROM mdm.asset_cut_context($3)) SELECT EXISTS(SELECT FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND (identity->>'device')::uuid=$2 AND kind IN('device','source','credential') AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,source_epoch,writer_xid) FROM input_cut),false))",
                results_published_on_1: concat!("SELECT s.resolution,s.resolution_revision,r.input FROM ", $scope_schema, "scopes s JOIN ", $scope_schema, "scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted"),
                results_source_rows_on_1: concat!("SELECT source,unknown,input FROM ", $scope_schema, "scope_source_members WHERE tenant_id=$1::uuid AND run=$2 AND input->'members' @> jsonb_build_array(jsonb_build_object('device',$3::uuid,'channel',$4::text)) ORDER BY source,object_kind,object_id LIMIT 16001"),
                results_historical_on_1: concat!("SELECT input FROM ", $scope_schema, "scope_runs WHERE tenant_id=$1::uuid AND scope=$2 AND id=$3 AND phase='published'"),
                results_source_devices_on_1: concat!("SELECT DISTINCT (member->>'device')::uuid AS device FROM ", $scope_schema, "scope_source_members CROSS JOIN LATERAL jsonb_array_elements(input->'members') member WHERE tenant_id=$1::uuid AND run=$2 AND source=ANY($3) AND member->>'channel'=$4 AND ($5::uuid IS NULL OR (member->>'device')::uuid>$5) ORDER BY device LIMIT $6"),
                results_source_objects_on_1: concat!("SELECT DISTINCT ON(object_kind,object_id) object_kind,object_id,input,unknown FROM ", $scope_schema, "scope_source_members WHERE tenant_id=$1::uuid AND run=$2 AND source=ANY($3) AND ($4::smallint IS NULL OR (object_kind,object_id)>($4,$5::uuid)) ORDER BY object_kind,object_id,unknown LIMIT $6"),
                projection_advance_1: concat!("INSERT INTO ", $scope_schema, "scope_projection_runs(tenant_id,id,scope,previous_resolution,next_entry,phase) VALUES($1::uuid,$2,$3,$4,$5,'sources') ON CONFLICT DO NOTHING"),
                projection_advance_2: concat!("SELECT * FROM ", $scope_schema, "scope_projection_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                projection_stage_1: concat!("SELECT m.source,m.object_kind,m.object_id,m.input FROM ", $scope_schema, "scope_source_members m JOIN ", $scope_schema, "scope_runs r ON(r.tenant_id,r.id)=(m.tenant_id,m.run) WHERE m.tenant_id=$1::uuid AND m.run=$2 AND r.input->'definition'->'targets' @> jsonb_build_array(r.input->'sources'->m.source->'reference') AND ($3::integer IS NULL OR (m.source,m.object_kind,m.object_id)>($3,$4::smallint,$5::uuid)) ORDER BY m.source,m.object_kind,m.object_id LIMIT 1001"),
                projection_stage_2: concat!("INSERT INTO ", $scope_schema, "scope_channel_results(tenant_id,run,channel,device,matched,pending,target,entry_revision) SELECT $1::uuid,$2,m->>'channel',(m->>'device')::uuid,false,count(DISTINCT m)>1,(array_agg(m ORDER BY m::text))[1],0 FROM unnest($3::jsonb[]) i CROSS JOIN LATERAL jsonb_array_elements(i->'members') m GROUP BY m->>'channel',m->>'device' ON CONFLICT(tenant_id,run,channel,device) DO UPDATE SET pending=", $scope_schema, "scope_channel_results.pending OR EXCLUDED.pending OR ", $scope_schema, "scope_channel_results.target IS DISTINCT FROM EXCLUDED.target"),
                projection_stage_3: concat!("UPDATE ", $scope_schema, "scope_projection_runs SET source_cursor_source=$3,source_cursor_kind=$4,source_cursor=$5,phase=$6 WHERE tenant_id=$1::uuid AND id=$2"),
                projection_project_1: concat!("SELECT channel,device FROM ", $scope_schema, "scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND ($3::text IS NULL OR (channel,device)>($3,$4::uuid)) ORDER BY channel,device LIMIT 17"),
                projection_project_2: concat!("SELECT DISTINCT m FROM ", $scope_schema, "scope_source_members s CROSS JOIN LATERAL jsonb_array_elements(s.input->'members') m WHERE s.tenant_id=$1::uuid AND s.run=$2 AND s.input->'members' @> jsonb_build_array(jsonb_build_object('device',$4::uuid,'channel',$3::text)) AND m->>'channel'=$3 AND (m->>'device')::uuid=$4"),
                projection_project_3: concat!("SELECT entry_revision FROM ", $scope_schema, "scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4 AND (matched OR pending) AND entry_revision>0 AND target=$5"),
                projection_project_4: concat!("UPDATE ", $scope_schema, "scope_channel_results SET matched=$5,pending=$6,target=$7,entry_revision=$8 WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4"),
                projection_project_5: concat!("UPDATE ", $scope_schema, "scope_projection_runs SET projection_cursor_channel=$3,projection_cursor=$4,phase=$5,channel_hashes=$6 WHERE tenant_id=$1::uuid AND id=$2"),
                projection_publish_1: concat!("SELECT o.id IS NULL OR n.channel_hashes->>'agent' IS DISTINCT FROM o.channel_hashes->>'agent',o.id IS NULL OR n.channel_hashes->>'mdm' IS DISTINCT FROM o.channel_hashes->>'mdm',coalesce(o.agent_revision,0),coalesce(o.mdm_revision,0) FROM ", $scope_schema, "scope_projection_runs n LEFT JOIN ", $scope_schema, "scope_projection_runs o ON(o.tenant_id,o.id)=(n.tenant_id,$3) WHERE n.tenant_id=$1::uuid AND n.id=$2 AND n.phase='ready' AND n.previous_resolution IS NOT DISTINCT FROM $3"),
                projection_publish_2: concat!("UPDATE ", $scope_schema, "scope_projection_runs SET phase='published',agent_revision=$3,mdm_revision=$4 WHERE tenant_id=$1::uuid AND id=$2"),
                projection_result_devices_on_1: concat!("SELECT NOT deleted AND resolution=$3 FROM ", $scope_schema, "scopes WHERE tenant_id=$1::uuid AND id=$2"),
                pages_scope_page_on_1: concat!("SELECT revision,resolution,deleted FROM ", $scope_schema, "scopes WHERE tenant_id=$1::uuid AND id=$2"),
                channels_targets_channel_state_on_1: concat!("SELECT ", $scope_schema, "channel_admission($1,$2,$3)"),
                channels_targets_published_admission_1: concat!("SELECT matched,pending,entry_revision FROM ", $scope_schema, "scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4"),
                channels_reader_rollout_input_on_1: concat!("SELECT s.resolution,CASE WHEN $3='mdm' THEN p.mdm_revision ELSE p.agent_revision END FROM (SELECT tenant_id,id,revision,resolution FROM ", $scope_schema, "scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted) s JOIN ", $scope_schema, "scope_projection_runs p ON(p.tenant_id,p.id)=(s.tenant_id,s.resolution) "),
                channels_reader_rollout_devices_on_1: concat!("WITH page AS (SELECT * FROM ", $scope_schema, r###"scope_channel_results WHERE tenant_id=$1::uuid AND run=$3 AND channel=$6 AND ($5::uuid IS NULL OR device>$5) ORDER BY device LIMIT 17) SELECT s.device,s.target,s.matched AND NOT s.pending AND EXISTS(SELECT 1 FROM "###, $scope_schema, "scope_channel_results r WHERE r.tenant_id=s.tenant_id AND r.run=$2 AND r.device=s.device AND r.channel=s.channel AND r.target=s.target AND r.matched AND NOT r.pending) AND NOT EXISTS(SELECT 1 FROM ", $scope_schema, "scope_channel_results e WHERE e.tenant_id=s.tenant_id AND e.run=ANY($4) AND e.channel=s.channel AND e.device=s.device AND (e.matched OR e.pending)) FROM page s ORDER BY s.device"),
                channels_query_coordinate: concat!("SELECT jsonb_build_array(s.revision,s.resolution) FROM (SELECT tenant_id,id,revision,resolution FROM ", $scope_schema, "scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted) s"),
            };
        }
    };
}
define_storage!(
    mdm,
    "mdm_policy.",
    "mdm_scope.",
    "mdm_access.",
    "mdm_access",
    "mdm_policy.versions",
    "mdm_policy.assignments",
    "mdm_policy.triggers",
    "mdm_policy.requests",
    "mdm_policy.work",
    "mdm_policy.schedule_scan",
    "mdm_policy.event_batches",
    "mdm_policy.event_members",
    "mdm_scope.tasks",
    "mdm_scope.asset_dispatch",
    "mdm_scope.group_changes",
    "mdm_owner",
    "mdm_policy_runtime",
    "mdm_scope_runtime",
    "mdm_command_runtime",
    "mdm_inventory_runtime"
);
define_storage!(
    da,
    "rss_da.",
    "rss_da.",
    "rss_da.",
    "da_access",
    "rss_da.policy_versions",
    "rss_da.policy_assignments",
    "rss_da.policy_triggers",
    "rss_da.policy_requests",
    "rss_da.policy_work",
    "rss_da.policy_schedule_scan",
    "rss_da.policy_event_batches",
    "rss_da.policy_event_members",
    "rss_da.scope_tasks",
    "rss_da.scope_asset_dispatch",
    "rss_da.scope_group_changes",
    "da_owner",
    "da_policy_runtime",
    "da_scope_runtime",
    "da_command_runtime",
    "da_inventory_runtime"
);
pub(crate) const fn sql(profile: StorageProfile) -> &'static Statements {
    match profile {
        StorageProfile::Mdm => &mdm::SQL,
        StorageProfile::Da => &da::SQL,
    }
}
