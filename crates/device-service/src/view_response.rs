//! Public projections assembled from Registration, Inventory and authorized Identity reads.
use crate::{Association, Error, Result, ViewRef};
use rss_mdm_inventory::{Evidence, FieldKey, ResolvedDeviceField, ResolvedField, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    #[serde(flatten)]
    pub registration: rss_mdm_registration_service::device::directory::Item,
    pub asset_state: crate::lifecycle_management::AssetState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<ResolvedField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<ResolvedField>,
    pub platform: Platform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_user: Option<RegistrationUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_user: Option<CurrentUser>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct Platform {
    pub state: PlatformState,
    #[schemars(extend("uniqueItems"=true))]
    pub values: Vec<rss_mdm_agent_wire::runtime::TaskPlatform>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformState {
    Known,
    Unknown,
    Conflict,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct RegistrationUser {
    #[serde(flatten)]
    pub registration: rss_mdm_registration_service::device::registration_user::RegistrationUser,
    pub display: Option<PersonDisplay>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentUser {
    pub revision: i64,
    pub state: UserState,
    pub user: Option<rss_mdm_authorization_service::User>,
    pub confirmed_at: Option<i64>,
    pub display: Option<PersonDisplay>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserState {
    Active,
    Invalidated,
    Unbound,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct PersonDisplay {
    pub login: Option<String>,
    pub profiles: Vec<PersonProfile>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonProfile {
    pub source: ProfileSource,
    pub status: ProfileStatus,
    pub display_name: Option<String>,
    pub username: Option<String>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileSource {
    IdentityLocal,
    Idp { provider: Uuid },
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    Available,
    Missing,
    Expired,
    Unavailable,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct Summary {
    pub reference: ViewRef,
    pub association: Option<Association>,
    pub endpoints: Vec<Endpoint>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct DirectoryRow {
    pub key: String,
    #[serde(flatten)]
    pub summary: Summary,
}
pub type Directory = rss_mdm_query::Page<rss_mdm_query::directory::Projection<DirectoryRow>>;
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Statistics {
    pub device_view_count: u64,
    pub endpoint_count: u64,
}
pub type StatisticsResponse = rss_mdm_query::Statistics<Statistics>;
pub(crate) enum DirectoryReply {
    Page(Directory),
    Statistics(StatisticsResponse),
}
impl DirectoryReply {
    pub(crate) fn page(self) -> Result<Directory> {
        if let Self::Page(v) = self {
            Ok(v)
        } else {
            Err(Error::Storage)
        }
    }
    pub(crate) fn statistics(self) -> Result<StatisticsResponse> {
        if let Self::Statistics(v) = self {
            Ok(v)
        } else {
            Err(Error::Storage)
        }
    }
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    #[serde(flatten)]
    pub summary: Summary,
    pub fields: BTreeMap<FieldKey, ResolvedDeviceField>,
    pub lists: BTreeMap<FieldKey, List>,
    pub inventory_sources: Vec<InventorySource>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct InventorySource {
    pub endpoint: String,
    pub quality: Vec<rss_mdm_inventory_service::assets::QualityRun>,
    pub revisions: BTreeMap<FieldKey, i64>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct List {
    pub state: ListState,
    pub sources: Vec<ListSource>,
    pub item_key: Option<String>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ListState {
    Known { count: usize, digest: String },
    Unknown { value: Unknown },
    Null,
    Missing,
    Unsupported,
    Deleted,
    Conflict,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct Unknown {
    pub reason: rss_mdm_inventory::UnknownReason,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSource {
    pub endpoint: String,
    pub evidence: Evidence,
    pub state: ListState,
    pub last_known: Option<ListKnown>,
    pub cursor: String,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
pub struct ListKnown {
    pub state: ListState,
    pub evidence: Evidence,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListItems {
    pub reference: ViewRef,
    pub field: FieldKey,
    pub source: Evidence,
    pub endpoint: String,
    pub total: usize,
    pub items: Vec<Scalar>,
    pub next_cursor: Option<String>,
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| Error::Storage)
}
