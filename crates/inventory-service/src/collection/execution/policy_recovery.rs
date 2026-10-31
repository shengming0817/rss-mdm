//! Policy changes wake all historical tasks, including after an action kind change.
use super::Transactions;
use crate::transaction::{Result, checked};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;
/// Locked business facts, prepared before the reconcile claim is protected.
pub(crate) struct Prepared {
    id: Uuid,
    row: sqlx::postgres::PgRow,
    current: Option<rss_mdm_policy::Policy>,
}
pub(crate) async fn prepare_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Prepared>> {
    service.validate_in(tx)?;
    let current = checked(service.policy_reader.locked_in(tx, id).await?)?;
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("SELECT * FROM mdm_inventory.collection_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE").bind(tenant).bind(id).fetch_optional(c).await
    })).await?;
    Ok(row.map(|row| Prepared { id, row, current }))
}
/// Advance the fixed revision window under the locks acquired by prepare_in.
pub(crate) async fn advance_in(
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
        let mut rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,Uuid>("SELECT r.id FROM mdm_inventory.collection_tasks r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND v.policy=$2 AND ($3::uuid IS NULL OR r.id>$3) ORDER BY r.id LIMIT 33").bind(tenant).bind(id).bind(after).fetch_all(c).await
        })).await?;
        done = rows.len() <= 32;
        rows.truncate(32);
        after = rows.last().copied();
        for run in rows {
            super::wake::run_in(&service.reconcile_messaging, tx, run).await?;
        }
    }
    let mut target_after: Option<String> = if fresh {
        None
    } else {
        row.try_get("target_after")?
    };
    let mut targets_done: bool = if fresh {
        false
    } else {
        row.try_get("targets_done")?
    };
    if !targets_done {
        let current = prepared.current.as_ref().filter(|p| {
            p.state.is_enabled()
                && p.definition.action.kind() == rss_mdm_policy::ActionKind::NativeCollection
        });
        if let Some(current) = current {
            let version = current.version;
            let tenant = tx.tenant_id().to_string();
            let cursor = target_after.clone();
            let mut rows=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("SELECT DISTINCT r.device COLLATE \"C\" AS device,r.id,r.generation FROM mdm_policy.assignments a JOIN mdm_access.registrations r ON r.tenant_id=a.tenant_id AND r.device=a.target->>'device' AND r.channel=a.channel AND r.state='active' AND r.purpose='primary' WHERE a.tenant_id=$1::uuid AND a.policy=$2 AND a.version=$3 AND a.availability='ready' AND r.device>coalesce($4,'') COLLATE \"C\" ORDER BY r.device COLLATE \"C\",r.id LIMIT 33")
                    .bind(tenant).bind(id).bind(version).bind(cursor).fetch_all(c).await
            })).await?;
            targets_done = rows.len() <= 32;
            rows.truncate(32);
            target_after = rows.last().map(|r| r.try_get("device")).transpose()?;
            for row in rows {
                super::scheduled::wake_in(
                    &service.reconcile_messaging,
                    tx,
                    super::scheduled::Work {
                        version,
                        registration: row.try_get("id")?,
                        generation: row.try_get("generation")?,
                    },
                )
                .await?;
            }
        } else {
            targets_done = true;
            target_after = None;
        }
    }
    let tenant = tx.tenant_id().to_string();
    let consumed = if done && targets_done {
        window
    } else {
        consumed
    };
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_inventory.collection_policy_recovery SET input_consumed=$3,input_window=$4,recovery_after=$5,runs_done=$6,target_after=$7,targets_done=$8 WHERE tenant_id=$1::uuid AND policy=$2")
            .bind(tenant).bind(id).bind(consumed).bind(window).bind(after).bind(done).bind(target_after).bind(targets_done).execute(c).await?;Ok(())
    })).await?;
    Ok(consumed < revision)
}
