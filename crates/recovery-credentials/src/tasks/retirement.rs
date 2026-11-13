//! Cancel exact Agent work using the initiating product's retirement authority and transaction.
use crate::tasks::{Error, transaction::Result};
use rss_mdm_audit_integration::{AuditIntent, Fact, RequestAudit, operation::OperationOwner};
use sqlx::Row;
use uuid::Uuid;
pub async fn retire_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    facts: &mut Vec<Fact>,
    tenant: &str,
    registration: rss_mdm_agent_wire::DeviceId,
) -> Result<()> {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        profile,
        tenant.to_owned(),
        "credential_revoke",
        AuditIntent::Management,
    );
    audit.identify_service("credential-retirement");
    audit.target_device(&registration);
    let candidates = match profile {
        rss_mdm_install_support::StorageProfile::Mdm => include_str!("retirement-mdm.sql"),
        rss_mdm_install_support::StorageProfile::Da => include_str!("retirement-da.sql"),
    };
    let mut after = Uuid::nil();
    loop {
        let rows = sqlx::query(candidates)
            .bind(tenant)
            .bind(registration.into_uuid())
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
                    crate::tasks::stored(serde_json::from_value(previous.clone()))?;
                state.cancel();
                sqlx::query_scalar::<_, bool>(
                    crate::storage_profile::sql(profile).tasks_retirement_retire_in_2,
                )
                .bind(registration.into_uuid())
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
            audit.owned_operation(
                OperationOwner::CredentialTask,
                id,
                "credential_revoke",
                AuditIntent::Management,
            );
            facts.push(Fact::business(
                &audit,
                OperationOwner::CredentialTask,
                &format!("credential-retirement:{registration}:task:{id}"),
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
    registrations: &[rss_mdm_agent_wire::DeviceId],
) -> Result<(bool, Option<Uuid>)> {
    let row: (bool, Option<Uuid>) =
        sqlx::query_as(crate::storage_profile::sql(profile).tasks_retirement_progress_on_1)
            .bind(tenant)
            .bind(
                registrations
                    .iter()
                    .map(|id| id.into_uuid())
                    .collect::<Vec<_>>(),
            )
            .fetch_one(c)
            .await?;
    Ok(row)
}
