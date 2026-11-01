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
                calculation_advance_in_1: concat!("SELECT EXISTS(SELECT FROM ", $access_schema, "asset_authority_history WHERE tenant_id=$1::uuid AND device=$2 AND NOT mdm.asset_visible($3,revision))"),
                results_published_on_1: concat!("SELECT s.resolution,s.resolution_revision,r.input FROM ", $scope_schema, "scopes s JOIN ", $scope_schema, "scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted"),
                results_source_rows_on_1: concat!("SELECT source,unknown,input FROM ", $scope_schema, "scope_source_members WHERE tenant_id=$1::uuid AND run=$2 AND input->'members' @> jsonb_build_array(jsonb_build_object('device',$3::text,'channel',$4::text)) ORDER BY source,device LIMIT 16001"),
                results_historical_on_1: concat!("SELECT input FROM ", $scope_schema, "scope_runs WHERE tenant_id=$1::uuid AND scope=$2 AND id=$3 AND phase='published'"),
                results_source_devices_on_1: concat!(r###"SELECT DISTINCT m->>'device' COLLATE "C" AS device FROM "###, $scope_schema, r###"scope_source_members s CROSS JOIN LATERAL jsonb_array_elements(s.input->'members') m WHERE s.tenant_id=$1::uuid AND s.run=$2 AND s.source=ANY($3) AND m->>'channel'=$4 AND m->>'device'>coalesce($5,'') COLLATE "C" ORDER BY device LIMIT $6"###),
                results_source_objects_on_1: concat!(r###"SELECT DISTINCT ON(object_key) object_key,input,unknown FROM (SELECT input,unknown,CASE input->'object'->>'kind' WHEN 'endpoint' THEN 'endpoint:'||(input->'object'->>'id') ELSE 'association:'||(input->'object'->>'id') END COLLATE "C" AS object_key FROM "###, $scope_schema, r###"scope_source_members WHERE tenant_id=$1::uuid AND run=$2 AND source=ANY($3)) objects WHERE object_key>coalesce($4,'') COLLATE "C" ORDER BY object_key,unknown LIMIT $5"###),
                projection_advance_1: concat!("INSERT INTO ", $scope_schema, "scope_projection_runs(tenant_id,id,scope,previous_resolution,next_entry,phase) VALUES($1::uuid,$2,$3,$4,$5,'sources') ON CONFLICT DO NOTHING"),
                projection_advance_2: concat!("SELECT * FROM ", $scope_schema, "scope_projection_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE"),
                projection_stage_1: concat!("SELECT m.source::text||':'||m.device AS key,m.input FROM ", $scope_schema, "scope_source_members m JOIN ", $scope_schema, r###"scope_runs r ON(r.tenant_id,r.id)=(m.tenant_id,m.run) WHERE m.tenant_id=$1::uuid AND m.run=$2 AND r.input->'definition'->'targets' @> jsonb_build_array(r.input->'sources'->m.source->'reference') AND (m.source::text||':'||m.device)>coalesce($3,'') COLLATE "C" ORDER BY (m.source::text||':'||m.device) COLLATE "C" LIMIT 1001"###),
                projection_stage_2: concat!("INSERT INTO ", $scope_schema, "scope_channel_results(tenant_id,run,channel,device,matched,pending,target,entry_revision) SELECT $1::uuid,$2,m->>'channel',m->>'device',false,count(DISTINCT m)>1,(array_agg(m ORDER BY m::text))[1],0 FROM unnest($3::jsonb[]) i CROSS JOIN LATERAL jsonb_array_elements(i->'members') m GROUP BY m->>'channel',m->>'device' ON CONFLICT(tenant_id,run,channel,device) DO UPDATE SET pending=", $scope_schema, "scope_channel_results.pending OR EXCLUDED.pending OR ", $scope_schema, "scope_channel_results.target IS DISTINCT FROM EXCLUDED.target"),
                projection_stage_3: concat!("UPDATE ", $scope_schema, "scope_projection_runs SET source_cursor=$3,phase=$4 WHERE tenant_id=$1::uuid AND id=$2"),
                projection_project_1: concat!("SELECT channel,device,channel||':'||device AS key FROM ", $scope_schema, r###"scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel||':'||device>coalesce($3,'') COLLATE "C" ORDER BY (channel||':'||device) COLLATE "C" LIMIT 17"###),
                projection_project_2: concat!("SELECT DISTINCT m FROM ", $scope_schema, "scope_source_members s CROSS JOIN LATERAL jsonb_array_elements(s.input->'members') m WHERE s.tenant_id=$1::uuid AND s.run=$2 AND s.input->'members' @> jsonb_build_array(jsonb_build_object('device',$4::text,'channel',$3::text)) AND m->>'channel'=$3 AND m->>'device'=$4"),
                projection_project_3: concat!("SELECT entry_revision FROM ", $scope_schema, "scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4 AND (matched OR pending) AND entry_revision>0 AND target=$5"),
                projection_project_4: concat!("UPDATE ", $scope_schema, "scope_channel_results SET matched=$5,pending=$6,target=$7,entry_revision=$8 WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4"),
                projection_project_5: concat!("UPDATE ", $scope_schema, "scope_projection_runs SET projection_cursor=$3,phase=$4,channel_hashes=$5 WHERE tenant_id=$1::uuid AND id=$2"),
                projection_publish_1: concat!("SELECT o.id IS NULL OR n.channel_hashes->>'agent' IS DISTINCT FROM o.channel_hashes->>'agent',o.id IS NULL OR n.channel_hashes->>'mdm' IS DISTINCT FROM o.channel_hashes->>'mdm',coalesce(o.agent_revision,0),coalesce(o.mdm_revision,0) FROM ", $scope_schema, "scope_projection_runs n LEFT JOIN ", $scope_schema, "scope_projection_runs o ON(o.tenant_id,o.id)=(n.tenant_id,$3) WHERE n.tenant_id=$1::uuid AND n.id=$2 AND n.phase='ready' AND n.previous_resolution IS NOT DISTINCT FROM $3"),
                projection_publish_2: concat!("UPDATE ", $scope_schema, "scope_projection_runs SET phase='published',agent_revision=$3,mdm_revision=$4 WHERE tenant_id=$1::uuid AND id=$2"),
                projection_result_devices_on_1: concat!("SELECT NOT deleted AND resolution=$3 FROM ", $scope_schema, "scopes WHERE tenant_id=$1::uuid AND id=$2"),
                pages_scope_page_on_1: concat!("SELECT revision,resolution,deleted FROM ", $scope_schema, "scopes WHERE tenant_id=$1::uuid AND id=$2"),
                channels_targets_channel_state_on_1: concat!("SELECT ", $scope_schema, "channel_admission($1,$2,$3)"),
                channels_targets_published_admission_1: concat!("SELECT matched,pending,entry_revision FROM ", $scope_schema, "scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4"),
                channels_reader_rollout_input_on_1: concat!("SELECT s.resolution,CASE WHEN $3='mdm' THEN p.mdm_revision ELSE p.agent_revision END FROM (SELECT tenant_id,id,revision,resolution FROM ", $scope_schema, "scopes WHERE tenant_id=$1::uuid AND id=$2 AND NOT deleted) s JOIN ", $scope_schema, "scope_projection_runs p ON(p.tenant_id,p.id)=(s.tenant_id,s.resolution) "),
                channels_reader_rollout_devices_on_1: concat!("WITH page AS (SELECT * FROM ", $scope_schema, r###"scope_channel_results WHERE tenant_id=$1::uuid AND run=$3 AND channel=$6 AND device>coalesce($5,'') COLLATE "C" ORDER BY device LIMIT 17) SELECT s.device,s.target,s.matched AND NOT s.pending AND EXISTS(SELECT 1 FROM "###, $scope_schema, "scope_channel_results r WHERE r.tenant_id=s.tenant_id AND r.run=$2 AND r.device=s.device AND r.channel=s.channel AND r.target=s.target AND r.matched AND NOT r.pending) AND NOT EXISTS(SELECT 1 FROM ", $scope_schema, "scope_channel_results e WHERE e.tenant_id=s.tenant_id AND e.run=ANY($4) AND e.channel=s.channel AND e.device=s.device AND (e.matched OR e.pending)) FROM page s ORDER BY s.device"),
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
