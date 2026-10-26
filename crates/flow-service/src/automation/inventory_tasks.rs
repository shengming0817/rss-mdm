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
    fn evaluation<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        task: Uuid,
    ) -> Pending<'a, Option<rss_mdm_inventory_service::assets::evaluation::EvaluationProgress>>
    {
        Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move {
                let binding:Option<String>=sqlx::query_scalar("SELECT binding FROM mdm_automation.inventory_evaluations WHERE tenant_id=$1::uuid AND task=$2")
                    .bind(&tenant).bind(task).fetch_optional(&mut *c).await?;
                let Some(binding)=binding else {return Ok(None)};
                let rows:Vec<(String,serde_json::Value)>=sqlx::query_as("SELECT version,state FROM mdm_automation.inventory_evaluation_arrays WHERE tenant_id=$1::uuid AND task=$2 ORDER BY version")
                    .bind(tenant).bind(task).fetch_all(c).await?;
                let arrays=rows.into_iter().map(|(v,state)|serde_json::from_value(state).map(|s|(v,s)).map_err(|_|sqlx::Error::Protocol("invalid inventory progress".into()))).collect::<Result<_,_>>()?;
                Ok(Some(rss_mdm_inventory_service::assets::evaluation::EvaluationProgress {binding,arrays}))
            })).await.map_err(|_|InventoryError::Unavailable(InventoryFailure::FlowStorage))
        })
    }
    fn save_evaluation<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        task: Uuid,
        progress: &'a rss_mdm_inventory_service::assets::evaluation::EvaluationProgress,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            let binding = progress.binding.clone();
            let arrays = progress
                .arrays
                .iter()
                .map(|(v, s)| serde_json::to_value(s).map(|s| (v.clone(), s)))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| InventoryError::Unavailable(InventoryFailure::FlowStorage))?;
            tx.with_connection(move|c|Box::pin(async move {
                let changed=sqlx::query("INSERT INTO mdm_automation.inventory_evaluations(tenant_id,task,binding) SELECT $1::uuid,$2,$3 WHERE EXISTS(SELECT 1 FROM mdm_automation.automation_jobs WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed) ON CONFLICT(tenant_id,task) DO UPDATE SET binding=EXCLUDED.binding WHERE inventory_evaluations.binding=EXCLUDED.binding")
                    .bind(&tenant).bind(task).bind(binding).execute(&mut *c).await?.rows_affected();
                if changed!=1 {return Err(sqlx::Error::Protocol("inventory progress identity".into()));}
                for (version,state) in arrays {
                    sqlx::query("INSERT INTO mdm_automation.inventory_evaluation_arrays(tenant_id,task,version,state) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,task,version) DO UPDATE SET state=EXCLUDED.state WHERE inventory_evaluation_arrays.state IS DISTINCT FROM EXCLUDED.state")
                        .bind(&tenant).bind(task).bind(version).bind(state).execute(&mut *c).await?;
                }
                Ok(())
            })).await.map_err(|_|InventoryError::Unavailable(InventoryFailure::FlowStorage))
        })
    }
    fn clear_evaluation<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        task: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("DELETE FROM mdm_automation.inventory_evaluations WHERE tenant_id=$1::uuid AND task=$2").bind(tenant).bind(task).execute(c).await?;
                Ok(())
            })).await.map_err(|_|InventoryError::Unavailable(InventoryFailure::FlowStorage))
        })
    }

    fn compliance_history<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        device: &'a str,
        bounds: rss_mdm_inventory_service::compliance::HistoryBounds,
        after: Option<rss_mdm_inventory_service::compliance::HistoryPosition>,
        limit: usize,
    ) -> Pending<'a, Vec<rss_mdm_inventory_service::compliance::HistoryRow>> {
        Box::pin(async move {
            use rss_mdm_inventory_service::compliance::{HistoryPosition, HistoryRow};
            use sqlx::Row;
            if !(1..=usize::from(rss_mdm_query::MAX_PAGE_LIMIT)).contains(&limit) {
                return Err(InventoryError::Malformed);
            }
            let tenant = tx.tenant_id().to_string();
            let device = device.to_owned();
            let rows=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("SELECT r.task,r.evaluated_at,r.document::text,j.failure FROM mdm_compliance.results r JOIN mdm_automation.automation_jobs j ON (j.tenant_id,j.id)=(r.tenant_id,r.task) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND j.completed AND j.kind='compliance' AND ($3::bigint IS NULL OR r.evaluated_at>=$3) AND ($4::bigint IS NULL OR r.evaluated_at<=$4) AND ($5::bigint IS NULL OR (r.evaluated_at,r.task)<($5,$6::uuid)) ORDER BY r.evaluated_at DESC,r.task DESC LIMIT $7")
                    .bind(tenant).bind(device).bind(bounds.from).bind(bounds.until).bind(after.map(|p|p.evaluated_at)).bind(after.map(|p|p.task)).bind((limit+1) as i64).fetch_all(c).await
            })).await.map_err(|_| InventoryError::Unavailable(InventoryFailure::FlowStorage))?;
            rows.into_iter()
                .map(|r| {
                    let decode = || -> Result<HistoryRow, sqlx::Error> {
                        Ok(HistoryRow {
                            position: HistoryPosition {
                                evaluated_at: r.try_get("evaluated_at")?,
                                task: r.try_get("task")?,
                            },
                            document: r.try_get("document")?,
                            failure: r.try_get("failure")?,
                        })
                    };
                    decode().map_err(|_| InventoryError::Unavailable(InventoryFailure::FlowStorage))
                })
                .collect()
        })
    }

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
