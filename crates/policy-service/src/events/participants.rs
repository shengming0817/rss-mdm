//! Policy requests only foreign execution admission and progress that it consumes.
use super::*;
use crate::inputs::Pending;
use crate::transaction::Fault;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    pub device: rss_mdm_agent_wire::DeviceId,
}
/// Concrete participants bound to the Policy event worker's transaction runtime.
pub struct MemberOwners {
    pub software: Arc<rss_mdm_software_service::deployment::Transactions>,
    pub enrollment: Arc<rss_mdm_registration_service::enrollment::tasks::Transactions>,
    pub credentials: Vec<Arc<rss_mdm_recovery_credentials::tasks::Transactions>>,
    pub scripts: Arc<rss_mdm_script_service::Transactions>,
    pub collections: Arc<rss_mdm_inventory_service::collection::execution::Transactions>,
}

impl MemberOwners {
    pub fn credentials(
        &self,
        profile: rss_mdm_install_support::StorageProfile,
    ) -> Result<&rss_mdm_recovery_credentials::tasks::Transactions> {
        self.credentials
            .iter()
            .find(|service| service.profile() == profile)
            .map(Arc::as_ref)
            .ok_or_else(|| Error::Unsupported.into())
    }
}

/// The host resolves an original operation to its single tenant-local owner.
pub trait OperationOwners: Send + Sync {
    fn event_parent_current_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: rss_mdm_agent_wire::DeviceId,
        run: Uuid,
    ) -> Pending<'a, bool, Fault>;
    fn policy_event_operation_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        reference: &'a wire::PolicyEventOperation,
    ) -> Pending<'a, EventOperationProgress, Fault>;
}

/// The actual operation owner's progress, retaining the established untagged HTTP shape.
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(untagged, rename_all_fields = "camelCase")]
pub enum EventOperationProgress {
    Collection {
        reference: wire::PolicyEventOperation,
        state: rss_mdm_inventory_service::collection::execution::model::NativeProgress,
        allowed_actions: [String; 0],
    },
    Run {
        reference: wire::PolicyEventOperation,
        state: rss_mdm_task_state::RunState,
        allowed_actions: [String; 0],
    },
    Native {
        reference: wire::PolicyEventOperation,
        #[serde(serialize_with = "serialize_native_status")]
        #[schemars(schema_with = "native_status_schema")]
        state: rss_device_command::Status,
        agent_installation:
            Option<rss_mdm_software_service::deployment::queries::records::InstallationObservation>,
        allowed_actions: [String; 0],
    },
    Retirement {
        reference: wire::PolicyEventOperation,
        state: rss_mdm_device_service::lifecycle::Retirement,
        allowed_actions: [String; 0],
    },
}
fn serialize_native_status<S: serde::Serializer>(
    status: &rss_device_command::Status,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(status.as_str())
}
fn native_status_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":"string","enum":rss_device_command::Status::ALL.map(|s|s.as_str())})
}
