//! Result retention is bounded independently of Inventory fact freshness.
use super::*;

impl AssetService {
    pub(in crate::assets) async fn software_result_state(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
    ) -> Result<ResultState> {
        let tenant = self.tenant.to_string();
        let state: String = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT result_state FROM mdm_assets.software_progress WHERE tenant_id=$1::uuid AND run=$2 FOR SHARE")
                .bind(tenant).bind(task).fetch_one(c).await
        })).await?;
        stored(serde_json::from_value(serde_json::json!(state)))
    }

    pub(super) async fn release_software_result(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
    ) -> Result<()> {
        // Take the same target lock as the worker BEFORE changing progress.
        self.reconcile_messaging
            .wake_in(
                tx,
                &crate::assets::tasks::target(self.tenant, task),
                &rss_reconcile::ResourceSet::empty(self.tenant),
                (),
                |_, _| Box::pin(async { Ok(()) }),
            )
            .await?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_assets.software_progress SET result_state='releasing' WHERE tenant_id=$1::uuid AND run=$2 AND result_state='retained'")
                .bind(tenant).bind(task).execute(c).await?;
            Ok(())
        })).await?;
        self.finish_query_in(tx, task, Some("cancelled")).await?;
        crate::wake::task(tx, "asset_queries").await?;
        Ok(())
    }

    pub(super) async fn software_release(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ReadScope,
        task: Uuid,
        change: &crate::operation::Operation<ReleaseInput>,
    ) -> Result<Response> {
        if change.expected_revision != 0 {
            return Err(Error::Malformed.into());
        }
        let state = self.query_task_in(tx, task).await?;
        if state.input.software.is_none() {
            return Err(Error::NotFound.into());
        }
        // A refreshed grant may release its own old result without reusing old authority.
        if state.input.scope.subject != scope.subject {
            return Err(Error::Forbidden.into());
        }
        self.release_software_result(tx, task).await?;
        Ok(Response::Mutation {
            receipt: MutationReceipt::ReleaseRequested { task },
        })
    }

    pub(super) async fn admit_software_result(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        let tenant = self.tenant.to_string();
        let runs: Vec<(Uuid, String, bool)> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text,3027))")
                .bind(&tenant).execute(&mut *c).await?;
            sqlx::query_as("SELECT p.run,p.result_state,r.completed FROM mdm_assets.software_progress p JOIN mdm_assets.asset_query_runs r ON(r.tenant_id,r.id)=(p.tenant_id,p.run) WHERE p.tenant_id=$1::uuid AND p.result_state<>'released' ORDER BY p.run LIMIT 32")
                .bind(tenant).fetch_all(c).await
        })).await?;
        if runs.len() >= 32 {
            return Err(Error::Unavailable(Failure::AssetObjectLimit).into());
        }
        // Refresh naturally revisits completed snapshots. No second timer or source TTL.
        for (task, state, completed) in runs {
            if state != "retained" || !completed {
                continue;
            }
            let old = self.query_task_in(tx, task).await?;
            let job = old
                .input
                .software
                .as_ref()
                .ok_or(Error::Unavailable(Failure::AssetsStorage))?;
            match self.software_current(tx, job).await {
                Ok(()) => (),
                Err(Fault::Request(Error::Conflict | Error::Forbidden | Error::NotFound)) => {
                    self.release_software_result(tx, task).await?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(in crate::assets) async fn clean_software_result(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
    ) -> Result<()> {
        // One bounded page per protected worker step; each delete is replay safe.
        for sql in [
            "DELETE FROM mdm_assets.software_evidence WHERE ctid IN (SELECT ctid FROM mdm_assets.software_evidence WHERE tenant_id=$1::uuid AND run=$2 LIMIT 1000)",
            "DELETE FROM mdm_assets.software_members WHERE ctid IN (SELECT ctid FROM mdm_assets.software_members WHERE tenant_id=$1::uuid AND run=$2 LIMIT 1000)",
            "DELETE FROM mdm_assets.software_objects WHERE ctid IN (SELECT ctid FROM mdm_assets.software_objects WHERE tenant_id=$1::uuid AND run=$2 LIMIT 1000)",
            "DELETE FROM mdm_assets.software_buckets WHERE ctid IN (SELECT ctid FROM mdm_assets.software_buckets WHERE tenant_id=$1::uuid AND run=$2 LIMIT 1000)",
        ] {
            let tenant = self.tenant.to_string();
            let deleted = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(sqlx::query(sql)
                            .bind(tenant)
                            .bind(task)
                            .execute(c)
                            .await?
                            .rows_affected())
                    })
                })
                .await?;
            if deleted > 0 {
                return Ok(());
            }
        }
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_assets.software_progress SET result_state='released',document=NULL,items=0,bytes=0 WHERE tenant_id=$1::uuid AND run=$2 AND result_state='releasing'")
                .bind(tenant).bind(task).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
}
