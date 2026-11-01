//! Policy reference facts consumed under the Scope initiating transaction.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use uuid::Uuid;
/// Whether any current Policy refers to the Scope, including rollout stages.
pub async fn used_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).scope_used_in_1)
                .bind(tenant)
                .bind(scope)
                .fetch_one(c)
                .await
        })
    })
    .await
}

/// A stable bounded page of Policies referring to a Scope or rollout stage.
pub async fn dependents_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    after: Option<String>,
) -> Result<Vec<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).scope_dependents_in_1)
                .bind(tenant)
                .bind(scope.to_string())
                .bind(after)
                .fetch_all(c)
                .await
        })
    })
    .await
}
