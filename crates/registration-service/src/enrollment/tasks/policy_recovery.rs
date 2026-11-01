//! Policy changes wake all historical tasks, including after an action kind change.
use crate::enrollment::tasks::{Result, Transactions};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;
/// Locked business facts, prepared before the reconcile claim is protected.
pub(crate) struct Prepared {
    id: Uuid,
    row: sqlx::postgres::PgRow,
}
pub(crate) async fn prepare_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Prepared>> {
    service.validate_in(tx)?;
    // Match management's Policy -> recovery row -> reconcile target order.
    crate::enrollment::tasks::transaction::checked(service.policy_reader.locked_in(tx, id).await?)?;
    let tenant = tx.tenant_id().to_string();
    let row = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    crate::storage_profile::sql(profile)
                        .enrollment_tasks_policy_recovery_prepare_in_1,
                )
                .bind(tenant)
                .bind(id)
                .fetch_optional(c)
                .await
            })
        })
        .await?;
    Ok(row.map(|row| Prepared { id, row }))
}
/// Advance the fixed revision window under the locks acquired by prepare_in.
pub(crate) async fn advance_in(
    profile: rss_mdm_install_support::StorageProfile,
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    prepared: &Prepared,
) -> Result<bool> {
    service.validate_in(tx)?;
    let id = prepared.id;
    let row = &prepared.row;

    let revision: i64 = row.try_get("input_revision")?;
    let consumed: i64 = row.try_get("input_consumed")?;
    let mut window: i64 = row.try_get("input_window")?;
    let mut after: Option<Uuid> = row.try_get("recovery_after")?;
    let mut done: bool = row.try_get("runs_done")?;
    let fresh = window == consumed;
    if fresh {
        window = revision;
        after = None;
        done = false;
    }
    if window == consumed {
        return Ok(false);
    }
    if !done {
        let tenant = tx.tenant_id().to_string();
        let mut rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, Uuid>(
                        crate::storage_profile::sql(profile)
                            .enrollment_tasks_policy_recovery_advance_in_1,
                    )
                    .bind(tenant)
                    .bind(id)
                    .bind(after)
                    .fetch_all(c)
                    .await
                })
            })
            .await?;
        done = rows.len() <= 32;
        rows.truncate(32);
        after = rows.last().copied();
        for run in rows {
            crate::enrollment::tasks::wake::run_in(profile, &service.reconcile_messaging, tx, run)
                .await?;
        }
    }
    let tenant = tx.tenant_id().to_string();
    let consumed = if done { window } else { consumed };
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(
                crate::storage_profile::sql(profile).enrollment_tasks_policy_recovery_advance_in_2,
            )
            .bind(tenant)
            .bind(id)
            .bind(consumed)
            .bind(window)
            .bind(after)
            .bind(done)
            .execute(c)
            .await?;
            Ok(())
        })
    })
    .await?;
    Ok(consumed < revision)
}
