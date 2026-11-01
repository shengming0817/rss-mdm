//! Cancel exact registration work without a second transaction or terminal-result mirror.
use crate::enrollment::tasks::{Error, transaction::Result};
use rss_mdm_audit_integration::{AuditIntent, Fact, RequestAudit};
use sqlx::Row;
use uuid::Uuid;
pub async fn retire_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    facts: &mut Vec<Fact>,
    tenant: &str,
    registration: Uuid,
) -> Result<()> {
    let audit = RequestAudit::new(
        tenant.to_owned(),
        "credential_revoke",
        AuditIntent::Management,
    );
    audit.identify_service("registration-retirement");
    audit.registration(registration);
    let mut after = Uuid::nil();
    loop {
        let rows = sqlx::query(
            crate::storage_profile::sql(profile).enrollment_tasks_retirement_retire_in_1,
        )
        .bind(tenant)
        .bind(registration)
        .bind(after)
        .fetch_all(&mut *c)
        .await?;
        let count = rows.len();
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            after = id;
            let previous: Option<serde_json::Value> = row.try_get("state")?;
            let changed = if let Some(previous) = previous {
                let mut state: rss_mdm_task_state::RunState =
                    crate::enrollment::tasks::stored(serde_json::from_value(previous.clone()))?;
                state.cancel();
                sqlx::query_scalar::<_, bool>(
                    crate::storage_profile::sql(profile).enrollment_tasks_retirement_retire_in_2,
                )
                .bind(registration)
                .bind(id)
                .bind(previous)
                .bind(serde_json::to_value(state).map_err(|_| Error::Malformed)?)
                .fetch_one(&mut *c)
                .await?
            } else {
                return Err(Error::Conflict.into());
            };
            if !changed {
                return Err(Error::Conflict.into());
            }
            audit.target(&id.to_string());
            facts.push(Fact::business(
                &audit,
                &format!("registration-retirement:{registration}:task:{id}"),
                200,
                "success",
                None,
            )?);
        }
        if count < 64 {
            break;
        }
    }
    audit.finalize(None);
    Ok(())
}

/// Pending execution and the first unconfirmed task across every retirement registration.
pub async fn progress_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registrations: &[Uuid],
) -> Result<(bool, Option<Uuid>)> {
    let row: (bool, Option<Uuid>) = sqlx::query_as(
        crate::storage_profile::sql(profile).enrollment_tasks_retirement_progress_on_1,
    )
    .bind(tenant)
    .bind(registrations)
    .fetch_one(c)
    .await?;
    Ok(row)
}
