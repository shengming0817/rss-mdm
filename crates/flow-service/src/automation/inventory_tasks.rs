use rss_mdm_inventory_service::{
    Error as InventoryError, Failure as InventoryFailure,
    tasks::{JobInput, Pending, State, Tasks},
};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
pub struct InventoryTasks;
pub fn failure(e: crate::transaction::Fault) -> InventoryError {
    use crate::{Error as F, Failure as U, transaction::Fault};
    match e {
        Fault::Request(e) => match e {
            F::Malformed => InventoryError::Malformed,
            F::Unauthorized => InventoryError::Unauthorized,
            F::Forbidden => InventoryError::Forbidden,
            F::NotFound => InventoryError::NotFound,
            F::Planning(crate::planning::error::PlanningError::Missing(m)) => {
                use crate::planning::error::Missing;
                use rss_mdm_inventory_service::groups::GroupMissing;
                match m {
                    Missing::Group => InventoryError::Group(GroupMissing::Group),
                    Missing::Rule => InventoryError::Group(GroupMissing::Rule),
                    Missing::Device => InventoryError::Group(GroupMissing::Device),
                    Missing::Scope | Missing::Policy => InventoryError::NotFound,
                }
            }

            F::Conflict => InventoryError::Conflict,
            F::CommitUnknown => InventoryError::CommitUnknown,
            F::RollbackFailed => InventoryError::RollbackFailed,
            F::Unavailable(f) => InventoryError::Unavailable(match f {
                U::Audit => InventoryFailure::Audit,
                U::AuditIntegrity => InventoryFailure::AuditIntegrity,
                U::AuditAdmission => InventoryFailure::AuditAdmission,
                U::AuditIsolation => InventoryFailure::AuditIsolation,
                U::AuditContract => InventoryFailure::AuditContract,
                U::RequestDeadline => InventoryFailure::RequestDeadline,
                _ => InventoryFailure::FlowStorage,
            }),
            _ => InventoryError::Unavailable(InventoryFailure::FlowStorage),
        },
        Fault::Sql(e)
            if e.as_database_error()
                .and_then(|e| e.code())
                .is_some_and(|c| c == "40001" || c == "40P01") =>
        {
            InventoryError::Conflict
        }
        Fault::Storage(e)
            if matches!(
                e.kind(),
                rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost
                    | rss_transactional_messaging::error::MessagingErrorKind::Conflict
            ) =>
        {
            InventoryError::Conflict
        }
        _ => InventoryError::Unavailable(InventoryFailure::FlowStorage),
    }
}

impl Tasks for InventoryTasks {
    fn enqueue<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        input: &'a JobInput,
    ) -> Pending<'a, serde_json::Value> {
        Box::pin(async move {
            let input = serde_json::from_value(
                serde_json::to_value(input).map_err(|_| InventoryError::Malformed)?,
            )
            .map_err(|_| InventoryError::Malformed)?;
            super::jobs::enqueue_job_in(tx, id, &input)
                .await
                .map_err(failure)
        })
    }
    fn read<'a, 'tx>(&'a self, tx: &'a mut PgTransaction<'tx>, id: Uuid) -> Pending<'a, State> {
        Box::pin(async move {
            let (input, done, failure_code, cursor, forwarded) =
                super::jobs::read_in(tx, id).await.map_err(failure)?;
            let input = serde_json::from_value(
                serde_json::to_value(input).map_err(|_| InventoryError::Malformed)?,
            )
            .map_err(|_| InventoryError::NotFound)?;
            Ok((input, done, failure_code, cursor, forwarded))
        })
    }
    fn finish<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        store: &'a rss_mdm_audit_integration::AuditStore,
        id: Uuid,
        reason: Option<&'a str>,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            super::jobs::finish_job_in(tx, store, id, reason)
                .await
                .map_err(failure)
        })
    }
    fn cursor<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        cursor: Option<String>,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let t = tx.tenant_id().to_string();
            tx.with_connection(move |c|Box::pin(async move {sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(t).bind(id.to_string()).bind(cursor).execute(c).await?;Ok(())})).await.map_err(|_| InventoryError::Unavailable(InventoryFailure::FlowStorage))
        })
    }
    fn detail<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
    ) -> Pending<'a, Option<serde_json::Value>> {
        Box::pin(async move {
            let t = tx.tenant_id().to_string();
            tx.with_connection(move |c|Box::pin(async move {sqlx::query_scalar("SELECT failure_detail FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(t).bind(id.to_string()).fetch_one(c).await})).await.map_err(|_| InventoryError::Unavailable(InventoryFailure::FlowStorage))
        })
    }
    fn set_detail<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        id: Uuid,
        detail: serde_json::Value,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let t = tx.tenant_id().to_string();
            tx.with_connection(move |c|Box::pin(async move {sqlx::query("UPDATE mdm_automation.automation_jobs SET failure_detail=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(t).bind(id.to_string()).bind(detail).execute(c).await?;Ok(())})).await.map_err(|_| InventoryError::Unavailable(InventoryFailure::FlowStorage))
        })
    }
}
