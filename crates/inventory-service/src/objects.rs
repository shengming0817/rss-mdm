//! Immutable association input. Inventory consumes explicit endpoint provenance only.
use rss_mdm_group_postgres::{AssetContext, Rejection};
use rss_mdm_registration_service::device::endpoints::PrimaryRegistration;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, sqlx::Error>> + Send + 'a>>;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    pub watermark: i64,
    pub version: String,
}
/// Borrow the caller's fenced transaction. No transaction, scheduler or credentials are owned here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipObjects {
    pub objects: Vec<ObjectRef>,
    pub current: bool,
}
pub trait ObjectReader: Send + Sync {
    fn memberships<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
    ) -> Pending<'a, MembershipObjects>;

    fn changes<'a>(
        &'a self,
        tenant: TenantId,
        after: u64,
        through: Option<u64>,
    ) -> Pending<'a, ChangeWindow>;
    fn freeze<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
    ) -> Pending<'a, ObjectSnapshot>;
    fn advance<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: &'a ObjectSnapshot,
    ) -> Pending<'a, SnapshotProgress>;
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
    fn validate<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        input: &'a DeviceObject,
        channel: rss_mdm_inventory::Channel,
    ) -> Pending<'a, Option<PrimaryRegistration>>;
    fn current<'a>(
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
    ) -> Pending<'a, Vec<DeviceObject>>;
}

#[derive(Clone, Debug)]
pub struct ChangeWindow {
    pub after: u64,
    pub through: Option<u64>,
    pub changed: bool,
}

/// A directory object, never an executable registration identity.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    pub fn from_group_input(input: &str) -> Result<Option<Self>, Rejection> {
        if !input.starts_with("objects:") {
            return Ok(None);
        }
        let parts: Vec<_> = input.split(':').collect();
        if parts.len() != 4 {
            return Err(Rejection::InvalidStoredDocument);
        }
        let id = Uuid::parse_str(parts[1]).map_err(|_| Rejection::InvalidStoredDocument)?;
        let watermark = parts[2]
            .parse::<i64>()
            .map_err(|_| Rejection::InvalidStoredDocument)?;
        if id.is_nil()
            || watermark < 0
            || parts[3].len() != 64
            || !parts[3].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Rejection::InvalidStoredDocument);
        }
        Ok(Some(Self {
            id,
            watermark,
            version: parts[3].into(),
        }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotProgress {
    Building,
    Ready,
    Superseded,
    ObjectLimit,
    ByteLimit,
}
