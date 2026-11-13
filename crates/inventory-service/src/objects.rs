//! Immutable association input. Inventory consumes explicit endpoint provenance only.
use rss_mdm_agent_wire::ObjectRef;
use rss_mdm_group::AssetContext;
use rss_mdm_group_postgres::Rejection;

use rss_mdm_registration_service::device::endpoints::PrimaryRegistration;
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use std::{future::Future, pin::Pin};
use uuid::Uuid;
/// Check the immutable asset universe without reinterpreting an object's identity.
pub fn checked_context(context: AssetContext, object: &ObjectRef) -> Result<ObjectRef, Rejection> {
    if object.uuid().is_nil()
        || (context == AssetContext::Endpoint && !matches!(object, ObjectRef::Endpoint(_)))
    {
        return Err(Rejection::InvalidStoredDocument);
    }
    Ok(*object)
}
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
    ) -> Pending<'a, Vec<ObjectRef>>;
    /// Conservative side-effect boundary, independent of targeting or read authorization.
    /// Unreleased links remain barriers while their identity is awaiting verification.
    fn effect_devices<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, Vec<rss_mdm_agent_wire::DeviceId>>;

    fn memberships<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, MembershipObjects>;

    /// Frozen objects containing this original endpoint/channel, never current heads.
    /// The byte allowance is checked before material is decoded. None means the
    /// allowance was insufficient, not that the snapshot contains no objects.
    fn memberships_at<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        snapshot: Uuid,
        device: &'a rss_mdm_agent_wire::DeviceId,
        channel: rss_mdm_inventory::Channel,
        max_bytes: usize,
    ) -> Pending<'a, Option<(Vec<DeviceObject>, usize)>>;

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
        max_bytes: usize,
    ) -> Pending<'a, Option<(DeviceObject, usize)>>;
    fn endpoint<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, DeviceObject>;
    /// Original endpoint membership as of the calculation's committed asset cut.
    fn endpoint_at<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        cut: &'a rss_mdm_inventory::AssetCut,
        device: &'a rss_mdm_agent_wire::DeviceId,
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
        after: Option<ObjectRef>,
        limit: usize,
        selected: Option<Vec<ObjectRef>>,
    ) -> Pending<'a, Vec<DeviceObject>>;
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

/// Why Device published an object version. Asset-only invalidation does not change execution eligibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectChangeKind {
    AssetInvalidated,
    IdentityChanged,
}
impl ObjectChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AssetInvalidated => "asset_invalidated",
            Self::IdentityChanged => "identity_changed",
        }
    }
}

/// One committed object change; old and new members remain available after replacement.
#[derive(Clone, Debug)]
pub struct ObjectChange {
    pub kind: ObjectChangeKind,
    pub position: i64,
    pub object: rss_mdm_agent_wire::ObjectRef,
    pub old_devices: Vec<rss_mdm_agent_wire::DeviceId>,
    pub new_devices: Vec<rss_mdm_agent_wire::DeviceId>,
}
