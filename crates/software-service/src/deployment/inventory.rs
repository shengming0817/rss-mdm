//! Software consumes current Inventory observations; it never reconstructs them from protocol rows.
use super::Error;
use rss_mdm_inventory::{AssetCut, ReportSource, channel::Observation};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{collections::BTreeMap, future::Future, pin::Pin};
use uuid::Uuid;
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
pub type Page = BTreeMap<(Uuid, i64, String), Observation>;
pub trait Inventory: Send + Sync {
    fn details_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        targets: &'a [(Uuid, i64, ReportSource)],
        lock: bool,
    ) -> Pending<'a, Page>;
    fn capture<'a>(
        &'a self,
        audit: &'a rss_mdm_audit_integration::AuditStore,
        tenant: TenantId,
        budget: &'a rss_mdm_audit_integration::budget::AuditBudget,
    ) -> Pending<'a, AssetCut>;
    fn detail_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        registration: Uuid,
        generation: i64,
        source: ReportSource,
    ) -> Pending<'a, Observation> {
        Box::pin(async move {
            Ok(self
                .details_on(c, tenant, &[(registration, generation, source)], true)
                .await?
                .remove(&(registration, generation, source.as_str().to_owned()))
                .unwrap_or(Observation::Unavailable))
        })
    }
}
