use super::*;
pub use rss_mdm_inventory::{FieldKey, Operator, Scalar};
use serde::{Deserialize, Serialize};
/// Collection selection is part of the rule, independent of caller authorization.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeSelector {
    Device,
    Exact {
        scope: Box<rss_mdm_inventory::CollectionScope>,
    },
    LocalUser {
        platform: rss_mdm_inventory::Platform,
        identity: String,
    },
    AllAuthorized,
}
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeQuantifier {
    One,
    Any,
    All,
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryCondition<C = Criteria> {
    pub selector: ScopeSelector,
    pub quantifier: ScopeQuantifier,
    pub criteria: C,
}
impl<C> InventoryCondition<C> {
    pub fn validate(&self) -> Result<()> {
        match &self.selector {
            ScopeSelector::Device => {
                if self.quantifier != ScopeQuantifier::One {
                    return Err(Error::Malformed.into());
                }
            }
            ScopeSelector::Exact { scope } => {
                checked_input(scope.validate_executable())?;
                if self.quantifier != ScopeQuantifier::One {
                    return Err(Error::Malformed.into());
                }
            }
            ScopeSelector::LocalUser { platform, identity } => {
                let valid = match platform {
                    rss_mdm_inventory::Platform::Windows => {
                        rss_mdm_inventory::LocalAccountIdentity::Windows {
                            sid: identity.clone(),
                        }
                        .validate()
                    }
                    rss_mdm_inventory::Platform::Macos => identity
                        .parse::<u32>()
                        .is_ok_and(|uid| uid > 0 && uid.to_string() == *identity),
                };
                if !valid || self.quantifier == ScopeQuantifier::One {
                    return Err(Error::Malformed.into());
                }
            }
            ScopeSelector::AllAuthorized => {
                if self.quantifier == ScopeQuantifier::One {
                    return Err(Error::Malformed.into());
                }
            }
        }
        Ok(())
    }
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Criteria {
    Predicate {
        field: FieldKey,
        op: Operator,
        #[serde(default)]
        value: Option<Scalar>,
        #[serde(default)]
        values: Option<Vec<Scalar>>,
    },
    And {
        children: Vec<Criteria>,
    },
    Or {
        children: Vec<Criteria>,
    },
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Sort {
    pub field: FieldKey,
    #[serde(default)]
    pub descending: bool,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    #[serde(default)]
    pub criteria: Option<InventoryCondition>,
    #[serde(default)]
    pub fields: Vec<FieldKey>,
    #[serde(default)]
    pub sort: Vec<Sort>,
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManualChange {
    Set { value: Scalar },
    Null {},
    Delete {},
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedDefinition {
    pub name: String,
    pub query: super::rsql::QueryInput,
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedChange {
    Put { definition: Box<SavedDefinition> },
    Delete {},
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Owner {
    pub instance: String,
    pub principal: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadScope {
    pub authority: String,
    pub collection_scope: rss_mdm_inventory::CollectionScope,
    pub subject: String,

    pub devices: Option<BTreeSet<String>>,
}
impl ReadScope {
    pub fn all() -> Self {
        Self {
            collection_scope: rss_mdm_inventory::CollectionScope::Device,
            subject: "group".into(),
            authority: "internal".into(),
            devices: None,
        }
    }
    pub fn from_proof(
        p: &crate::authorization::context::AuthorizedPrincipal,
    ) -> std::result::Result<Self, Error> {
        Self::from_snapshot(p, p.authorization()?)
    }
    pub(super) fn from_snapshot(
        p: &crate::authorization::context::AuthorizedPrincipal,
        snapshot: &crate::authorization::Snapshot,
    ) -> std::result::Result<Self, Error> {
        Ok(Self {
            collection_scope: rss_mdm_inventory::CollectionScope::Device,
            subject: format!("{}:{}", p.instance_id(), p.principal_id()),
            devices: snapshot.inventory_devices(p)?,
            authority: snapshot.query_binding(p)?,
        })
    }
    pub fn full(&self) -> std::result::Result<(), AssetError> {
        if self.devices.is_none() {
            Ok(())
        } else {
            Err(AssetError::RestrictedScope)
        }
    }
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceView {
    pub collection_scope: rss_mdm_inventory::CollectionScope,
    pub device: String,
    pub channels: BTreeSet<String>,
    pub fields: BTreeMap<FieldKey, rss_mdm_inventory::ResolvedField>,
    pub lists: BTreeMap<FieldKey, super::lists::ListSummary>,
    pub quality: Vec<QualityRun>,
    pub revisions: BTreeMap<FieldKey, i64>,
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryScope {
    pub scope: rss_mdm_inventory::CollectionScope,
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedView {
    pub id: Uuid,
    pub revision: i64,
    pub definition: Option<SavedDefinition>,
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Summary {
    pub matched: usize,
    pub unknown: usize,
    pub total: usize,
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Response {
    InventoryScopes {
        device: String,
        watermark: i64,
        items: Vec<InventoryScope>,
        next_cursor: Option<String>,
    },
    FieldLayout {
        revision: u64,
        editable: bool,
        groups: Vec<super::FieldDisplayGroup>,
    },
    FieldLayoutWritten {
        revision: u64,
    },
    RetentionPolicy {
        policy: Option<rss_mdm_inventory::RetentionPolicy>,
    },
    CollectionItems {
        run: Uuid,
        field: FieldKey,
        items: Vec<ItemQualityView>,
        next_cursor: Option<String>,
    },
    ListItems {
        device: String,
        field: FieldKey,
        watermark: i64,
        total: usize,
        items: Vec<Scalar>,
        next_cursor: Option<String>,
    },
    #[serde(skip_deserializing)]
    CollectionRun {
        run: Box<super::runs::RunView>,
    },
    Field {
        field: FieldKey,
        version: u64,
        definition: Option<Box<rss_mdm_inventory::FieldDefinition>>,
    },
    FieldReferences {
        field: FieldKey,
        impact: super::FieldImpact,
        mappings: Vec<super::FieldMappingReference>,
        next_cursor: Option<String>,
    },
    QueryStatus {
        task: Uuid,
        status: String,
        summary: Summary,
        failure: Option<String>,
        result_url: Option<String>,
    },
    Facets {
        task: Uuid,
        facet: Facet,
        items: Vec<FacetCount>,
        next_cursor: Option<String>,
    },
    Accepted {
        task: Uuid,
        status_url: String,
    },
    #[serde(skip_deserializing)]
    FieldList {
        dictionary: String,
        items: Vec<rss_mdm_query::directory::Projection<super::FieldView>>,
        next_cursor: Option<String>,
    },
    FieldDescriptor {
        field: Box<super::FieldView>,
    },
    Detail {
        device: DeviceView,
    },
    Page {
        items: Vec<DeviceView>,
        next_cursor: Option<String>,
        snapshot: String,
        summary: Summary,
    },
    Assignment {
        device: String,
        field: FieldKey,
        revision: i64,
    },
    Saved {
        query: SavedView,
    },
    #[serde(skip_deserializing)]
    SavedList {
        items: Vec<rss_mdm_query::directory::Projection<super::saved_directory::Row>>,
        #[serde(rename = "nextCursor")]
        next_cursor: Option<String>,
    },
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Command {
    InventoryScopes {
        device: String,
        scope: ReadScope,
        limit: usize,
        cursor: Option<String>,
    },
    FieldLayoutRead {
        access: super::FieldLayoutAccess,
    },
    FieldLayoutWrite {
        change: Operation<super::FieldLayout>,
    },
    RetentionWrite {
        change: Operation<rss_mdm_inventory::RetentionPolicy>,
    },
    RetentionRead {
        key: String,
        revision: u64,
    },
    CollectionItems {
        device: String,
        run: Uuid,
        field: FieldKey,
        scope: ReadScope,
        cursor: Option<String>,
        limit: usize,
    },
    ListItems {
        device: String,
        field: FieldKey,
        scope: ReadScope,
        limit: usize,
        cursor: Option<String>,
    },
    CollectionRun {
        device: String,
        run: Uuid,
        scope: ReadScope,
    },
    FieldWrite {
        field: FieldKey,
        change: Operation<super::FieldChange>,
    },
    FieldReferences {
        field: FieldKey,
        query: super::FieldReferenceQuery,
    },
    QueryStatus {
        task: Uuid,
        scope: ReadScope,
    },
    QueryItems {
        task: Uuid,
        scope: ReadScope,
        limit: usize,
        cursor: Option<String>,
    },
    QueryFacets {
        task: Uuid,
        scope: ReadScope,
        facet: Facet,
        limit: usize,
        cursor: Option<String>,
    },
    Detail {
        device: String,
        scope: ReadScope,
    },
    Search {
        request: Box<Operation<super::rsql::QueryInput>>,
        scope: ReadScope,
    },
    Manual {
        device: String,
        field: FieldKey,
        change: Operation<ManualChange>,
        owner: Owner,
    },
    SavedRead {
        owner: Owner,
        id: Uuid,
    },
    SavedWrite {
        owner: Owner,
        id: Uuid,
        change: Operation<SavedChange>,
    },
    SavedExecute {
        operation: Uuid,
        expected_revision: u64,
        owner: Owner,
        id: Uuid,
        scope: ReadScope,
    },
}
impl Command {
    pub fn operation(&self) -> Option<Uuid> {
        match self {
            Self::FieldLayoutWrite { change } => Some(change.operation_id),
            Self::FieldWrite { change, .. } => Some(change.operation_id),
            Self::RetentionWrite { change } => Some(change.operation_id),
            Self::Search { request, .. } => Some(request.operation_id),
            Self::SavedExecute { operation, .. } => Some(*operation),
            Self::Manual { change, .. } => Some(change.operation_id),
            Self::SavedWrite { change, .. } => Some(change.operation_id),
            _ => None,
        }
    }
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualityRun {
    pub dataset: String,
    pub template_version: String,
    pub fingerprint: String,
    #[schemars(schema_with = "rss_mdm_inventory::coverage_schema")]
    pub coverage: rss_observation::Coverage,
    pub complete: bool,
    pub source: rss_mdm_inventory::Source,
    pub channel: rss_mdm_inventory::Channel,
    pub registration: Uuid,
    pub registration_generation: u64,
    pub epoch: Uuid,
    pub run_id: Uuid,
    pub sequence: i64,
    pub result: crate::collection::RunResult,
    pub delivery_pending: bool,
    pub fields: Vec<QualityField>,
}
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualityField {
    pub reason: Option<String>,
    pub scope: rss_mdm_inventory::CollectionScope,
    pub item_count: usize,
    pub invalid_items: usize,
    pub field: FieldKey,
    pub quality: crate::collection::Quality,
    pub status: Option<u16>,
    pub received_at: Option<i64>,
}

#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Facet {
    OsVersions,
    Channels,
    AssetStates,
}
impl Facet {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::OsVersions => "os_versions",
            Self::Channels => "channels",
            Self::AssetStates => "asset_states",
        }
    }
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacetCount {
    pub label: String,
    pub total: u64,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ItemQualityView {
    pub index: usize,
    pub quality: crate::collection::Quality,
    /// Validated row evidence, independent of the whole field's snapshot eligibility.
    pub value: Option<Scalar>,
}
