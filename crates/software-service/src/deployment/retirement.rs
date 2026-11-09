//! Device lifecycle remains authoritative for the exact cleanup execution it accepted.
use super::Error;
use sqlx::PgConnection;
use std::{collections::BTreeMap, future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
pub struct Context {
    pub policy: Uuid,
    pub version: Uuid,
    pub lifetime: u32,
    pub origin: rss_mdm_audit_integration::activity::ActivityOrigin,
    pub target: super::scope::DeviceObject,
}
pub struct Channel {
    pub device: String,
}
pub trait Lifecycle: Send + Sync {
    fn cleanup_allowed_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        retirement: Uuid,
        device: &'a str,
        execution: Option<Uuid>,
    ) -> Pending<'a, bool>;
    fn context_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        retirement: Uuid,
    ) -> Pending<'a, Context>;
    fn authorize_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        retirement: Uuid,
        registration: String,
        execution: Uuid,
    ) -> Pending<'a, ()>;
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit owner participants and caller authority retain the borrowed connection and exact operation identity"
    )]
    fn blocked_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: rss_request_context::TenantId,
        retirement: Uuid,
        registration: String,
        reason: &'static str,
        execution: Option<Uuid>,
        unknown: bool,
    ) -> Pending<'a, ()>;
    fn wake_in<'a>(
        &'a self,
        messaging: &'a rss_reconcile_postgres::PgMessagingStore,
        tx: &'a mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        device: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = super::Result<()>> + Send + 'a>>;

    fn execution_allowed_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        device: &'a str,
        execution: Uuid,
    ) -> Pending<'a, bool>;
    fn execution_permissions_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        targets: &'a [(Uuid, String)],
    ) -> Pending<'a, BTreeMap<Uuid, bool>>;
}

pub async fn cleanup_allowed_in(
    lifecycle: std::sync::Arc<dyn Lifecycle>,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    retirement: Uuid,
    device: &str,
    execution: Option<Uuid>,
) -> super::Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(lifecycle
                    .cleanup_allowed_on(c, &tenant, retirement, &device, execution)
                    .await)
            })
        })
        .await??)
}
pub async fn context_in(
    lifecycle: std::sync::Arc<dyn Lifecycle>,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    retirement: Uuid,
) -> super::Result<Context> {
    let tenant = tx.tenant_id();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(lifecycle.context_on(c, tenant, retirement).await) })
        })
        .await??)
}

mod cleanup;

mod registration;
pub use registration::retire_in;

pub async fn progress_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registrations: &[String],
) -> crate::deployment::Result<(bool, Option<uuid::Uuid>)> {
    Ok(sqlx::query_as("SELECT count(*) > 0, ((array_agg(id ORDER BY id) FILTER (WHERE priority = 0)))[1] FROM (SELECT id, CASE WHEN state ->> 'execution' = 'unknown' THEN 0 ELSE 1 END AS priority FROM mdm_software_deployment.action_runs WHERE tenant_id = CAST($1 AS uuid) AND device = ANY($2) AND state ->> 'execution' IN ('running', 'waiting_reboot', 'unknown') UNION ALL SELECT o.id, CASE WHEN d.terminal_at IS NOT NULL THEN 0 ELSE 1 END AS priority FROM mdm_software_deployment.operations AS o INNER JOIN rss_device_command.commands AS d ON (d.tenant_id, d.command_id) = (o.tenant_id, CAST(o.id AS text)) WHERE o.tenant_id = CAST($1 AS uuid) AND o.device = ANY($2) AND (d.terminal_at IS NULL OR (d.status <> 'applied' AND (EXISTS (SELECT 1 FROM mdm_windows.attempts AS a WHERE (a.tenant_id, a.operation) = (o.tenant_id, o.id) AND a.phase = 'execute') OR EXISTS (SELECT 1 FROM mdm_apple.attempts AS a WHERE (a.tenant_id, a.operation) = (o.tenant_id, o.id) AND a.phase = 'execute' AND a.state <> 'pending'))))) AS pending").bind(tenant).bind(registrations).fetch_one(c).await?)
}
