use super::*;
pub(crate) use rss_mdm_inventory::{FieldKey, Operator, Scalar};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Criteria {
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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Sort {
    pub field: FieldKey,
    #[serde(default)]
    pub descending: bool,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Query {
    #[serde(default)]
    pub criteria: Option<Criteria>,
    #[serde(default)]
    pub select: Vec<FieldKey>,
    #[serde(default)]
    pub sort: Option<Sort>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ManualChange {
    Set { value: Scalar },
    Null {},
    Delete {},
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SavedDefinition {
    pub name: String,
    pub query: Query,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum SavedChange {
    Put { definition: SavedDefinition },
    Delete {},
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Owner {
    pub instance: String,
    pub principal: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadScope {
    pub subject: String,
    pub devices: Option<BTreeSet<String>>,
}
impl ReadScope {
    pub(in crate::management) fn all() -> Self {
        Self {
            subject: "group".into(),
            devices: None,
        }
    }
    pub(crate) fn from_proof(p: &crate::identity::Principal) -> std::result::Result<Self, Error> {
        Ok(Self {
            subject: format!("{}:{}", p.instance_id(), p.principal_id()),
            devices: p.authorization()?.inventory_devices(p)?,
        })
    }
    pub(crate) fn full(&self) -> std::result::Result<(), Error> {
        if self.devices.is_none() {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeviceView {
    pub device: String,
    pub channels: BTreeSet<String>,
    pub fields: BTreeMap<FieldKey, rss_mdm_inventory::ResolvedField>,
    pub quality: Vec<QualityRun>,
    pub revisions: BTreeMap<FieldKey, i64>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SavedView {
    pub id: Uuid,
    pub revision: i64,
    pub definition: Option<SavedDefinition>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Summary {
    pub matched: usize,
    pub unknown: usize,
    pub total: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum Response {
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
    Fields {
        dictionary: String,
        fields: Vec<serde_json::Value>,
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
    SavedList {
        items: Vec<SavedView>,
        next: Option<Uuid>,
    },
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Command {
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
    Fields,
    Detail {
        device: String,
        scope: ReadScope,
    },
    Search {
        request: Operation<Query>,
        scope: ReadScope,
    },
    Manual {
        device: String,
        field: FieldKey,
        change: Operation<ManualChange>,
        owner: Owner,
    },
    SavedList {
        owner: Owner,
        after: Option<Uuid>,
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
    pub(crate) fn operation(&self) -> Option<Uuid> {
        match self {
            Self::Search { request, .. } => Some(request.operation_id),
            Self::SavedExecute { operation, .. } => Some(*operation),
            Self::Manual { change, .. } => Some(change.operation_id),
            Self::SavedWrite { change, .. } => Some(change.operation_id),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QualityRun {
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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QualityField {
    pub field: FieldKey,
    pub quality: crate::collection::Quality,
    pub status: Option<u16>,
    pub received_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Facet {
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FacetCount {
    pub label: String,
    pub total: u64,
}
