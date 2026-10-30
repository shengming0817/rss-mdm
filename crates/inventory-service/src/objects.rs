//! Immutable association input. Inventory consumes explicit endpoint provenance only.
use rss_mdm_group::AssetContext;
use rss_mdm_group_postgres::Rejection;

use rss_mdm_registration_service::device::endpoints::PrimaryRegistration;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, sqlx::Error>> + Send + 'a>>;
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceObject {
    pub object: ObjectRef,
    pub association_version: Option<i64>,
    pub verified: bool,
    pub members: Vec<PrimaryRegistration>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectSnapshot {
    pub id: Uuid,
    pub asset_cut: rss_mdm_inventory::AssetCut,
    pub version: String,
}
/// Borrow the caller's fenced transaction. No transaction, scheduler or credentials are owned here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipObjects {
    pub objects: Vec<ObjectRef>,
    pub current: bool,
}
pub trait ObjectReader: Send + Sync {
    fn changes<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        after: i64,
        through: i64,
        limit: usize,
    ) -> Pending<'a, Vec<ObjectChange>>;
    fn change_head<'a>(&'a self, c: &'a mut PgConnection, tenant: TenantId) -> Pending<'a, i64>;

    fn changed<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        from: Uuid,
        to: Uuid,
    ) -> Pending<'a, Vec<String>>;
    /// Conservative side-effect boundary, independent of targeting or read authorization.
    /// Unreleased links remain barriers while their identity is awaiting verification.
    fn effect_devices<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, Vec<String>>;

    fn memberships<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, MembershipObjects>;

    fn relation_revision<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
    ) -> Pending<'a, u64>;
    fn capture<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        after: Option<Uuid>,
    ) -> Pending<'a, ObjectSnapshot>;
    fn lookup<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: Uuid,
        object: &'a ObjectRef,
    ) -> Pending<'a, DeviceObject>;
    fn endpoint<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, DeviceObject>;
    /// Original endpoint membership as of the calculation's committed asset cut.
    fn endpoint_at<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        cut: &'a rss_mdm_inventory::AssetCut,
        device: &'a str,
    ) -> Pending<'a, DeviceObject>;
    fn validate<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        input: &'a DeviceObject,
        channel: rss_mdm_inventory::Channel,
    ) -> Pending<'a, Option<PrimaryRegistration>>;
    fn complete<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: &'a ObjectSnapshot,
    ) -> Pending<'a, bool>;
    fn page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: Uuid,
        after: Option<String>,
        limit: usize,
        selected: Option<Vec<String>>,
    ) -> Pending<'a, Vec<DeviceObject>>;
}

/// A directory object, never an executable registration identity.
#[derive(
    schemars::JsonSchema, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ObjectRef {
    /// One original endpoint.
    Endpoint(String),
    /// One product association whose members must be resolved by its owner.
    Association(Uuid),
}
impl ObjectRef {
    /// Decode the adapter's opaque key under its fixed asset universe.
    pub fn from_key(context: AssetContext, key: &str) -> Result<Self, Rejection> {
        match context {
            AssetContext::Endpoint => Ok(Self::Endpoint(key.into())),
            AssetContext::AssociatedDevice => {
                if let Some(id) = key.strip_prefix("endpoint:") {
                    return Ok(Self::Endpoint(id.into()));
                }
                let id = key
                    .strip_prefix("association:")
                    .ok_or(Rejection::InvalidStoredDocument)?;
                let id = Uuid::parse_str(id).map_err(|_| Rejection::InvalidStoredDocument)?;
                if id.is_nil() {
                    return Err(Rejection::InvalidStoredDocument);
                }
                Ok(Self::Association(id))
            }
        }
    }
    /// Stable unified-universe key, kept separate from endpoint identity.
    pub fn key(&self) -> String {
        match self {
            Self::Endpoint(id) => format!("endpoint:{id}"),
            Self::Association(id) => format!("association:{id}"),
        }
    }
}

impl ObjectSnapshot {
    pub fn group_input(&self) -> String {
        format!(
            "objects:{}",
            serde_json::to_string(self).expect("object snapshot serialization")
        )
    }
    pub fn from_group_input(input: &str) -> Result<Option<Self>, Rejection> {
        if !input.starts_with("objects:") {
            return Ok(None);
        }
        let snapshot: Self =
            serde_json::from_str(input.strip_prefix("objects:").expect("checked prefix"))
                .map_err(|_| Rejection::InvalidStoredDocument)?;
        if snapshot.id.is_nil()
            || snapshot.version.len() != 64
            || !snapshot.version.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Rejection::InvalidStoredDocument);
        }
        Ok(Some(snapshot))
    }
}

/// One committed object change; old and new members remain available after replacement.
#[derive(Clone, Debug)]
pub struct ObjectChange {
    pub position: i64,
    pub object: String,
    pub old_devices: Vec<String>,
    pub new_devices: Vec<String>,
}
