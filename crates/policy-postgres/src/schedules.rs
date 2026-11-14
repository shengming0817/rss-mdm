//! Persisted Policy schedules and explicit triggers, interpreted by the application.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use uuid::Uuid;
/// Bounded unexpired triggers for an immutable publication.
pub async fn triggers_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    now: i64,
) -> Result<Vec<(Uuid, i64)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_as(crate::storage_profile::sql(profile).schedules_triggers_in_1)
                .bind(tenant)
                .bind(version)
                .bind(now)
                .fetch_all(c)
                .await
        })
    })
    .await
}
/// A bounded page of enabled retirement publications.
pub async fn retirement_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    after: Option<Uuid>,
) -> Result<Vec<(Uuid, Uuid, Value)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_as(crate::storage_profile::sql(profile).schedules_retirement_in_1)
                .bind(tenant)
                .bind(after)
                .fetch_all(c)
                .await
        })
    })
    .await
}

/// Whether a bounded calendar discovery page is due.
pub async fn scan_due_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    now: i64,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).schedules_scan_due_in_1)
                .bind(tenant)
                .bind(now)
                .fetch_one(c)
                .await
        })
    })
    .await
}
/// Resume a calendar discovery cycle under the initiating RSS claim.
pub async fn scan_cursor_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
) -> Result<Option<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).schedules_scan_cursor_in_2)
                .bind(tenant)
                .fetch_one(c)
                .await
        })
    })
    .await
}
/// Advance only with the occurrence work created by this page.
pub async fn complete_scan_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    after: Option<Uuid>,
    next: i64,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).schedules_complete_scan_in_1)
                .bind(tenant)
                .bind(after)
                .bind(next)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}

/// Register lifecycle scans in the original accepted Policy transaction.
pub async fn accept_scan_in(
    profile: rss_mdm_install_support::StorageProfile,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).schedules_scan_cursor_in_1)
                .bind(tenant)
                .bind(binding.epoch().get())
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
