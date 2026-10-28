use crate::{Error as InventoryError, Failure as InventoryFailure, tasks::Pending};
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
impl crate::assets::evaluation::EvaluationStore for super::Groups {
    fn evaluation<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        task: Uuid,
    ) -> Pending<'a, Option<crate::assets::evaluation::EvaluationProgress>> {
        Box::pin(async move {
            self.runtime
                .validate_transaction(tx)
                .map_err(|_| InventoryError::Unavailable(InventoryFailure::Runtime))?;
            if tx.tenant_id() != self.tenant {
                return Err(InventoryError::Forbidden);
            }
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move {
                let binding:Option<String>=sqlx::query_scalar("SELECT binding FROM mdm_assets.group_evaluations WHERE tenant_id=$1::uuid AND task=$2")
                    .bind(&tenant).bind(task).fetch_optional(&mut *c).await?;
                let Some(binding)=binding else {return Ok(None)};
                let rows:Vec<(String,serde_json::Value)>=sqlx::query_as("SELECT version,state FROM mdm_assets.group_evaluation_arrays WHERE tenant_id=$1::uuid AND task=$2 ORDER BY version")
                    .bind(tenant).bind(task).fetch_all(c).await?;
                let arrays=rows.into_iter().map(|(v,state)|serde_json::from_value(state).map(|s|(v,s)).map_err(|_|sqlx::Error::Protocol("invalid inventory progress".into()))).collect::<Result<_,_>>()?;
                Ok(Some(crate::assets::evaluation::EvaluationProgress {binding,arrays}))
            })).await.map_err(|_|InventoryError::Unavailable(InventoryFailure::AssetsStorage))
        })
    }
    fn save_evaluation<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        task: Uuid,
        progress: &'a crate::assets::evaluation::EvaluationProgress,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.runtime
                .validate_transaction(tx)
                .map_err(|_| InventoryError::Unavailable(InventoryFailure::Runtime))?;
            if tx.tenant_id() != self.tenant {
                return Err(InventoryError::Forbidden);
            }
            let tenant = tx.tenant_id().to_string();
            let binding = progress.binding.clone();
            let arrays = progress
                .arrays
                .iter()
                .map(|(v, s)| serde_json::to_value(s).map(|s| (v.clone(), s)))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| InventoryError::Unavailable(InventoryFailure::AssetsStorage))?;
            tx.with_connection(move|c|Box::pin(async move {
                let changed=sqlx::query("INSERT INTO mdm_assets.group_evaluations(tenant_id,task,binding) SELECT $1::uuid,$2,$3 WHERE EXISTS(SELECT 1 FROM mdm_assets.group_tasks WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed) ON CONFLICT(tenant_id,task) DO UPDATE SET binding=EXCLUDED.binding WHERE group_evaluations.binding=EXCLUDED.binding")
                    .bind(&tenant).bind(task).bind(binding).execute(&mut *c).await?.rows_affected();
                if changed!=1 {return Err(sqlx::Error::Protocol("inventory progress identity".into()));}
                for (version,state) in arrays {
                    sqlx::query("INSERT INTO mdm_assets.group_evaluation_arrays(tenant_id,task,version,state) VALUES($1::uuid,$2,$3,$4) ON CONFLICT(tenant_id,task,version) DO UPDATE SET state=EXCLUDED.state WHERE group_evaluation_arrays.state IS DISTINCT FROM EXCLUDED.state")
                        .bind(&tenant).bind(task).bind(version).bind(state).execute(&mut *c).await?;
                }
                Ok(())
            })).await.map_err(|_|InventoryError::Unavailable(InventoryFailure::AssetsStorage))
        })
    }
    fn clear_evaluation<'a, 'tx>(
        &'a self,
        tx: &'a mut PgTransaction<'tx>,
        task: Uuid,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.runtime
                .validate_transaction(tx)
                .map_err(|_| InventoryError::Unavailable(InventoryFailure::Runtime))?;
            if tx.tenant_id() != self.tenant {
                return Err(InventoryError::Forbidden);
            }

            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("DELETE FROM mdm_assets.group_evaluations WHERE tenant_id=$1::uuid AND task=$2").bind(tenant).bind(task).execute(c).await?;
                Ok(())
            })).await.map_err(|_|InventoryError::Unavailable(InventoryFailure::AssetsStorage))
        })
    }
}
