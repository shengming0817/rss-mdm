//! Policy owns the complete desired-configuration lifecycle and its command participation.
use crate::{Error, Failure, transaction::*};
use rss_device_command::{self as dc, Store as _};
use rss_mdm_audit_integration::RequestAudit;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use std::sync::Arc;
use uuid::Uuid;
mod authority;
mod candidates;
pub mod channels;
mod claims;
pub mod definition;
pub mod frozen;
mod input_storage;
pub mod model;
mod policies;
mod protection;
mod queue;
pub mod storage;
pub use definition::{Configuration, Object, Owner, Protected};
pub use model::{Create, NativeTarget, Task};
pub struct Transactions {
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) changes: Arc<dyn crate::inputs::ExecutionChanges>,
    pub(crate) outbox: Arc<rss_transactional_messaging_postgres::PgOutboxStore<()>>,
    pub(crate) tenant: TenantId,
    pub(crate) protection: Arc<rss_mdm_native_protection::Protector>,
    pub(crate) policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub(crate) source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    pub(crate) store: rss_device_command_postgres::PgStore<()>,
    pub(crate) reconcile_messaging: rss_reconcile_postgres::PgMessagingStore,
    pub(crate) audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub(crate) channels: Arc<dyn channels::Channels>,
    pub(crate) runtime: Arc<PgRuntime>,
}
impl Transactions {
    pub async fn reconcile_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        self.reconcile_configuration_target_in(tx, device, audit, None)
            .await
    }
    async fn required_command(
        &self,
        tx: &mut PgTransaction<'_>,
        op: &storage::Operation,
    ) -> Result<dc::Command> {
        self.store
            .load(tx, op.scope, &op.command_id()?)
            .await?
            .ok_or_else(|| Error::Unavailable(Failure::CommandInvariant).into())
    }
}
fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(Failure::Database)
}
pub fn recovery_scope(tenant: TenantId) -> rss_reconcile::Scope {
    rss_reconcile::Scope::new(tenant, "mdm.policy").expect("configuration scope")
}
fn target(tenant: TenantId, device: &rss_mdm_agent_wire::DeviceId) -> rss_reconcile::Target {
    use sha2::{Digest, Sha256};
    rss_reconcile::Target::new(
        recovery_scope(tenant),
        format!(
            "configuration:{:x}",
            Sha256::digest(device.to_string().as_bytes())
        ),
    )
    .expect("configuration target")
}

impl Transactions {
    async fn dispatched_in(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<bool> {
        let tenant = tx.tenant_id();
        Ok(tx
            .with_connection_context(&mut (self, id), move |ctx, c| {
                Box::pin(async move { Ok(ctx.0.channels.execute_was_sent(c, tenant, ctx.1).await) })
            })
            .await??)
    }
}
fn messaging_domain() -> rss_transactional_messaging::message::MessagingDomain {
    rss_transactional_messaging::message::MessagingDomain::parse("mdm.policy.configuration.v1")
        .expect("configuration domain")
}

pub const INSTALL_SQL: &str = include_str!("../../schema/configuration.sql");
pub const RELATIONS_SQL: &str = include_str!("../../schema/configuration-relations.sql");

pub mod publication;

mod events;

mod binding;
pub use binding::Dependencies;
pub(crate) mod recovery;
pub mod wake;

pub(crate) mod source_changes;
pub const SOURCE_CHANGES_SQL: &str = include_str!("../../schema/configuration-source-changes.sql");

pub mod apple;
pub mod protocol;
pub mod windows;

mod windows_wake;

pub mod retirement;

pub mod assets;

pub mod queries;

pub mod preview;

pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");
mod admission;
pub use admission::verify_authority;

pub(crate) fn device_id(
    id: uuid::Uuid,
) -> std::result::Result<rss_mdm_agent_wire::DeviceId, sqlx::Error> {
    rss_mdm_agent_wire::DeviceId::try_from(id).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}
pub(crate) fn device_ids(
    ids: Vec<uuid::Uuid>,
) -> std::result::Result<Vec<rss_mdm_agent_wire::DeviceId>, sqlx::Error> {
    ids.into_iter().map(device_id).collect()
}
