//! Capture fixed asset input using the existing read capability before source work.
use rss_mdm_audit_integration::{AuditStore, budget::AuditBudget};
use rss_mdm_inventory::AssetCut;
use rss_request_context::TenantId;

/// Finish and release the read transaction before acquiring any business transaction.
/// The caller's absolute budget is borrowed; this does not restart its deadline.
pub async fn capture(
    store: &AuditStore,
    tenant: TenantId,
    budget: &AuditBudget,
) -> Result<AssetCut, crate::Error> {
    store
        .read(tenant, &budget.control(), tenant, |tenant, tx| {
            Box::pin(async move {
                let tenant = *tenant;
                Ok::<_, rss_mdm_audit_integration::Error>(
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            rss_mdm_inventory_postgres::capture_asset_cut_on_read(c, tenant).await
                        })
                    })
                    .await?,
                )
            })
        })
        .await
        .fold(
            Ok,
            |_| Err(crate::Error::Unavailable(crate::Failure::AssetsStorage)),
            |_| Err(crate::Error::Unavailable(crate::Failure::AssetsStorage)),
            |_| Err(crate::Error::RollbackFailed),
            |_| Err(crate::Error::Unavailable(crate::Failure::AssetsStorage)),
            |_| Err(crate::Error::Unavailable(crate::Failure::AssetsStorage)),
        )
}
