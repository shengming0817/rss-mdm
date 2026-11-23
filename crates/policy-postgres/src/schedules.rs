//! Persisted Policy schedules and explicit triggers, interpreted by the application.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use uuid::Uuid;
/// Fix the upper bound of one Scope publication's scan.
pub async fn trigger_bound_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    now: i64,
) -> Result<Option<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).trigger_scan_bound)
                .bind(tenant)
                .bind(version)
                .bind(now)
                .fetch_optional(c)
                .await
        })
    })
    .await
}

/// One ordered page through a fixed upper bound, including one lookahead row.
pub async fn trigger_page_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    now: i64,
    page: crate::work::TriggerPage,
    limit: u16,
) -> Result<Vec<(Uuid, i64, i64)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_as(crate::storage_profile::sql(profile).trigger_page)
                .bind(tenant)
                .bind(version)
                .bind(now)
                .bind(page.after)
                .bind(page.through)
                .bind(i64::from(limit) + 1)
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
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    let epoch = tx.expected_epoch().get();

    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).schedules_scan_cursor_in_1)
                .bind(tenant)
                .bind(epoch)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
