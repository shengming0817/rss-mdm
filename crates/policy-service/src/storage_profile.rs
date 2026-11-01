//! Fixed, owner-owned SQL. Only these source literals can select objects.
use rss_mdm_install_support::StorageProfile;
pub(crate) struct Statements {
    pub admission: &'static str,
    pub events_event_device_current_in_1: &'static str,
    pub events_event_scope_in_1: &'static str,
    pub management_lifecycle_advance_lifecycle_work_in_1: &'static str,
}
macro_rules! define_storage {
    ($module:ident, $policy_schema:literal, $scope_schema:literal, $access_schema:literal, $access_role:literal, $policy_versions:literal, $policy_assignments:literal, $policy_triggers:literal, $policy_requests:literal, $policy_work:literal, $policy_schedule_scan:literal, $policy_event_batches:literal, $policy_event_members:literal, $scope_tasks:literal, $scope_asset_dispatch:literal, $scope_group_changes:literal, $owner:literal, $policy_runtime:literal, $scope_runtime:literal, $command_runtime:literal, $inventory_runtime:literal) => {
        mod $module {
            pub(super) const SQL: super::Statements = super::Statements {
                admission: concat!("SELECT NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid IN('", $policy_schema, "policies'::regclass,'", $policy_versions, "'::regclass,'", $policy_assignments, r###"'::regclass) AND c.relkind='r' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)))

 AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='"###, $access_schema, r###"collection_runs'::regclass)
 AND NOT has_table_privilege(current_user,'"###, $access_schema, r###"collection_runs','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege(current_user,'"###, $access_schema, r###"collection_runs','INSERT,UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='"###, $access_schema, r###"collection_runs'::regclass AND a.attnum>0 AND NOT a.attisdropped
  AND has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')<>(a.attname IN('tenant_id','scope','id','result','attempts','evidence','sequence','sealed_at')))
"###),
                events_event_device_current_in_1: concat!("SELECT EXISTS(SELECT 1 FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2 AND device=$3 AND generation=$4 AND state='active')"),
                events_event_scope_in_1: concat!("SELECT channel FROM ", $access_schema, "registrations WHERE tenant_id=$1::uuid AND id=$2"),
                management_lifecycle_advance_lifecycle_work_in_1: concat!("SELECT ", $policy_schema, "lock_policy($1)"),
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
