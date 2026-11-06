use crate::{
    assets,
    objects::{DeviceObject, ObjectRef, ObjectSnapshot},
    operation::Operation,
};
use rss_mdm_group::{AssetContext, GroupSource};
use rss_mdm_inventory::{AssetCut, Evidence, Platform, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
}

#[derive(schemars::JsonSchema, Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assessment {
    pub threshold: Option<u64>,
    /// None disables assessment; an enabled union cannot be empty.
    pub allowed_groups: Option<Vec<Uuid>>,
}
#[derive(schemars::JsonSchema, Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assessments {
    #[serde(default)]
    pub endpoint: Assessment,
    #[serde(default)]
    pub associated_device: Assessment,
}
impl Assessments {
    pub fn get(&self, context: AssetContext) -> &Assessment {
        match context {
            AssetContext::Endpoint => &self.endpoint,
            AssetContext::AssociatedDevice => &self.associated_device,
        }
    }
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Standard {
    pub name: String,
    pub risk: Risk,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub assessments: Assessments,
}
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum SoftwareSource {
    #[serde(rename = "device.software.installations")]
    Installations,
    #[serde(rename = "device.software.windows.win32")]
    WindowsWin32,
    #[serde(rename = "device.software.windows.store")]
    WindowsStore,
    #[serde(rename = "device.software.windows.non_store")]
    WindowsNonStore,
    #[serde(rename = "device.software.windows.system")]
    WindowsSystem,
    #[serde(rename = "device.software.apple.installed_applications")]
    AppleApplications,
}
impl SoftwareSource {
    pub const ALL: [Self; 6] = [
        Self::Installations,
        Self::WindowsWin32,
        Self::WindowsStore,
        Self::WindowsNonStore,
        Self::WindowsSystem,
        Self::AppleApplications,
    ];
    pub fn field(self) -> &'static str {
        match self {
            Self::Installations => "device.software.installations",
            Self::WindowsWin32 => "device.software.windows.win32",
            Self::WindowsStore => "device.software.windows.store",
            Self::WindowsNonStore => "device.software.windows.non_store",
            Self::WindowsSystem => "device.software.windows.system",
            Self::AppleApplications => "device.software.apple.installed_applications",
        }
    }
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mapping {
    pub standard: Uuid,
    pub enabled: bool,
    pub source: SoftwareSource,
    pub platform: Platform,
    /// Source-native origin. Mandatory for the multi-origin installations field.
    pub origin: Option<String>,
    /// RSQL over one installation item, never independent array leaf sets.
    pub filter: String,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "action",
    content = "definition",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Change<T> {
    Put(T),
    Delete,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record<T> {
    pub id: Uuid,
    pub revision: u64,
    pub definition: Option<T>,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Combine {
    Union,
    Intersection,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupFilter {
    pub combine: Combine,
    pub ids: Vec<Uuid>,
}
#[derive(schemars::JsonSchema, Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareFilter {
    #[serde(default)]
    pub standards: Vec<Uuid>,
    #[serde(default)]
    pub risks: Vec<Risk>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Name, nativeId, version, publisher, platform, origin, source and component.
    pub filter: Option<String>,
}
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    Version,
    Component,
    Publisher,
    Platform,
    Os,
    Architecture,
    DeviceGroup,
}
fn default_context() -> AssetContext {
    AssetContext::AssociatedDevice
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    #[serde(default = "default_context")]
    pub context: AssetContext,
    #[serde(default)]
    pub devices: assets::rsql::QueryInput,
    pub groups: Option<GroupFilter>,
    #[serde(default)]
    pub software: SoftwareFilter,
    #[serde(default)]
    pub dimensions: Vec<Dimension>,
}
#[derive(schemars::JsonSchema, Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Page {
    pub limit: usize,
    pub cursor: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Access {
    pub(in crate::assets) scope: assets::ReadScope,
    pub(super) authorities: Vec<(
        rss_mdm_authorization_service::Permission,
        rss_mdm_authorization_service::OperationAuthority,
    )>,
}
impl Access {
    pub fn from_proof(
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    ) -> Result<Self, crate::Error> {
        use rss_mdm_authorization_service::{OperationAuthority as Authority, Permission as P};
        let scope = assets::ReadScope::from_proof(proof)?;
        if scope.devices.is_some() {
            return Err(crate::Error::Forbidden);
        }
        let snapshot = proof.authorization()?;
        Ok(Self {
            scope,
            authorities: vec![
                (
                    P::InventoryRead,
                    Authority::all_devices(snapshot, proof, P::InventoryRead)?,
                ),
                (
                    P::InventorySensitiveRead,
                    Authority::tenant(snapshot, proof, P::InventorySensitiveRead)?,
                ),
                (
                    P::GroupRead,
                    Authority::tenant(snapshot, proof, P::GroupRead)?,
                ),
            ],
        })
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Command {
    Standards {
        page: Page,
    },
    Standard {
        id: Uuid,
    },
    PutStandard {
        id: Uuid,
        change: Operation<Change<Standard>>,
    },
    Mappings {
        page: Page,
    },
    Mapping {
        id: Uuid,
    },
    PutMapping {
        id: Uuid,
        change: Operation<Change<Mapping>>,
    },
    Receipt {
        id: Uuid,
        actor: String,
        instance: String,
    },
    Search {
        change: Box<Operation<Query>>,
    },
    Status {
        id: Uuid,
    },
    Buckets {
        id: Uuid,
        page: Page,
    },
    Coverage {
        id: Uuid,
        page: Page,
    },
    Breakdowns {
        id: Uuid,
        bucket: String,
        dimension: Dimension,
        page: Page,
    },
    Devices {
        id: Uuid,
        bucket: String,
        page: Page,
    },
    Evidence {
        id: Uuid,
        bucket: String,
        object: String,
        page: Page,
    },
}
impl Command {
    pub fn operation(&self) -> Option<Uuid> {
        match self {
            Self::PutStandard { change, .. } => Some(change.operation_id),
            Self::PutMapping { change, .. } => Some(change.operation_id),
            Self::Search { change } => Some(change.operation_id),
            _ => None,
        }
    }
    pub fn writes_configuration(&self) -> bool {
        matches!(self, Self::PutStandard { .. } | Self::PutMapping { .. })
    }
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compliance {
    Disabled,
    Compliant,
    NonCompliant,
    Unknown,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdState {
    Disabled,
    Below,
    Reached,
    Unknown,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    Standard {
        id: Uuid,
        name: String,
        risk: Risk,
        tags: Vec<String>,
    },
    Unmapped {
        name: String,
        source: SoftwareSource,
        native_id: String,
        publisher: String,
        platform: Platform,
    },
    Conflict {
        name: String,
        candidates: Vec<Uuid>,
        rules: Vec<Uuid>,
    },
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bucket {
    pub id: String,
    pub identity: Identity,
    pub devices: u64,
    pub assessment_devices: u64,
    pub threshold: Option<u64>,
    pub threshold_state: ThresholdState,
    pub compliance: ComplianceCounts,
}
#[derive(schemars::JsonSchema, Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComplianceCounts {
    pub disabled: u64,
    pub compliant: u64,
    pub non_compliant: u64,
    pub unknown: u64,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Breakdown {
    pub value: String,
    pub devices: u64,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Device {
    pub object: ObjectRef,
    pub compliance: Compliance,
    pub group_decisions: BTreeMap<Uuid, Decision>,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Match,
    NoMatch,
    Unknown,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallationEvidence {
    pub endpoint: String,
    pub source: SoftwareSource,
    pub evidence: Evidence,
    pub array_version: String,
    pub ordinal: usize,
    pub value: Scalar,
    pub rules: Vec<Uuid>,
    pub confirmed: bool,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Quality {
    pub endpoint: String,
    pub source: SoftwareSource,
    pub scope: rss_mdm_inventory::CollectionScope,
    pub state: assets::lists::ListState,
    pub last_known: Vec<RetainedEvidence>,
    pub runs: Vec<assets::QualityRun>,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedEvidence {
    pub array_version: String,
    pub count: usize,
    pub evidence: Evidence,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Coordinates {
    pub asset_cut: AssetCut,
    pub configuration_revision: u64,
    pub association_revision: u64,
    pub object_snapshot: Option<Uuid>,
    pub object_version: Option<String>,
    pub context: AssetContext,
    pub groups: Vec<GroupSource>,
    pub as_of: i64,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum MutationReceipt {
    Written {
        resource: String,
        id: Uuid,
        revision: u64,
    },
    Accepted {
        task: Uuid,
        status_url: String,
    },
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Response {
    Standard {
        record: Record<Standard>,
    },
    Standards {
        items: Vec<Record<Standard>>,
        next_cursor: Option<String>,
    },
    Mapping {
        record: Record<Mapping>,
    },
    Mappings {
        items: Vec<Record<Mapping>>,
        next_cursor: Option<String>,
    },
    Mutation {
        receipt: MutationReceipt,
    },
    Receipt {
        operation: Uuid,
        receipt: Option<MutationReceipt>,
    },
    Status {
        task: Uuid,
        status: String,
        failure: Option<String>,
        coordinates: Coordinates,
        processed: u64,
        unknown: u64,
    },
    Coverage {
        task: Uuid,
        coordinates: Coordinates,
        items: Vec<CoverageItem>,
        next_cursor: Option<String>,
    },
    Buckets {
        task: Uuid,
        coordinates: Coordinates,
        items: Vec<Bucket>,
        next_cursor: Option<String>,
    },
    Breakdowns {
        task: Uuid,
        coordinates: Coordinates,
        items: Vec<Breakdown>,
        next_cursor: Option<String>,
    },
    Devices {
        task: Uuid,
        coordinates: Coordinates,
        items: Vec<Device>,
        next_cursor: Option<String>,
    },
    Evidence {
        task: Uuid,
        coordinates: Coordinates,
        items: Vec<InstallationEvidence>,
        quality: Vec<Quality>,
        next_cursor: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Configuration {
    pub revision: u64,
    pub standards: Vec<Record<Standard>>,
    pub mappings: Vec<Record<Mapping>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub query: Query,
    pub(super) predicates: BTreeMap<Uuid, super::filter::Predicate>,
    pub(super) software_predicate: Option<super::filter::Predicate>,
    pub(super) configuration: Configuration,
    pub coordinates: Coordinates,
    pub objects: Option<ObjectSnapshot>,
    pub group_ready: BTreeMap<Uuid, bool>,
    pub authorities: Vec<(
        rss_mdm_authorization_service::Permission,
        rss_mdm_authorization_service::OperationAuthority,
    )>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ObjectProgress {
    pub object: DeviceObject,
    pub matched: bool,
    pub unknown: bool,
    pub coverage_unknown: bool,
    pub groups: BTreeMap<Uuid, Decision>,
    pub dimensions: BTreeMap<Dimension, Vec<String>>,
    pub arrays: Vec<ArrayInput>,
    pub array: usize,
    pub scan: Option<rss_mdm_inventory_postgres::arrays::ArrayScanState>,
    pub published_after: Option<String>,
    pub quality: Vec<Quality>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ArrayInput {
    pub endpoint: String,
    pub source: SoftwareSource,
    pub platform: Platform,
    pub evidence: Evidence,
    pub value: rss_mdm_inventory::ArrayValue,
    pub confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ObjectResult {
    pub matched: bool,
    pub unknown: bool,
    pub object: ObjectRef,
    pub groups: BTreeMap<Uuid, Decision>,
    pub quality: Vec<Quality>,
}

#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageItem {
    pub object: ObjectRef,
    pub matched: bool,
    pub unknown: bool,
    pub quality: Vec<Quality>,
}
