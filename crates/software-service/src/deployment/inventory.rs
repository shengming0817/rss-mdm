//! Software consumes current Inventory observations; it never reconstructs them from protocol rows.
use super::Error;
use rss_mdm_inventory::{AssetCut, ReportSource, channel::Observation};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::{collections::BTreeMap, future::Future, pin::Pin};
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
pub type Page = BTreeMap<(rss_mdm_agent_wire::DeviceId, String), Observation>;
pub trait Inventory: Send + Sync {
    fn details_on<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        targets: &'a [(rss_mdm_agent_wire::DeviceId, ReportSource)],
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
        device: rss_mdm_agent_wire::DeviceId,
        source: ReportSource,
    ) -> Pending<'a, Observation> {
        Box::pin(async move {
            Ok(self
                .details_on(c, tenant, &[(device, source)], true)
                .await?
                .remove(&(device, source.as_str().to_owned()))
                .unwrap_or(Observation::Unavailable))
        })
    }
}
