//! One six-second fact snapshot followed by a fresh authorization read under its fence.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.9.0
use crate::{Error, Service};
use rss_mdm_authorization_service::{Snapshot, context::AuthorizedPrincipal};
use sqlx::Acquire;
impl Service {
    pub(crate) async fn snapshot<C: Send, R: Send, F>(
        &self,
        proof: &AuthorizedPrincipal,
        mut context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'c> FnOnce(
                &'c mut C,
                &'c mut sqlx::PgConnection,
                &'c Snapshot,
                i64,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<R, Error>> + Send + 'c>,
            > + Send,
    {
        proof.check_live().map_err(|_| Error::Denied)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Denied);
        }
        let start = self.clock.now();
        let remaining = || {
            std::time::Duration::from_secs(6)
                .saturating_sub(self.clock.now().saturating_duration_since(start))
        };
        let deadline = || Error::Storage;
        let mut connection = tokio::time::timeout(remaining(), self.read_pool.acquire())
            .await
            .map_err(|_| deadline())?
            .map_err(sql)?;
        let result=tokio::time::timeout(remaining(),async {
            let mut tx=connection.begin().await.map_err(sql)?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await.map_err(sql)?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)").bind(self.tenant.to_string()).bind(remaining().as_millis().max(1).to_string()).execute(&mut *tx).await.map_err(sql)?;
            let grant=rss_mdm_authorization_service::snapshot_on(rss_mdm_install_support::StorageProfile::Mdm, &mut tx,proof.tenant_id(),proof.instance_id()).await.map_err(|_|Error::Storage)?;
            let binding=grant.query_binding(proof).map_err(|_|Error::Denied)?;
            let now=sqlx::query_scalar("SELECT floor(extract(epoch FROM transaction_timestamp()))::bigint").fetch_one(&mut *tx).await.map_err(sql)?;
            let value=operation(&mut context,&mut tx,&grant,now).await?;
            tx.rollback().await.map_err(sql)?;
            Ok::<_,Error>((value,binding))
        }).await;
        let (value, binding) = match result {
            Ok(Ok(v)) => v,
            other => {
                connection.close_on_drop();
                return Err(match other {
                    Ok(Err(e)) => e,
                    Err(_) => deadline(),
                    _ => unreachable!(),
                });
            }
        };
        drop(connection);
        let mut connection = tokio::time::timeout(remaining(), self.read_pool.acquire())
            .await
            .map_err(|_| deadline())?
            .map_err(sql)?;
        let result=tokio::time::timeout(remaining(),async {
            let mut tx=connection.begin().await.map_err(sql)?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY").execute(&mut *tx).await.map_err(sql)?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)").bind(self.tenant.to_string()).bind(remaining().as_millis().max(1).to_string()).execute(&mut *tx).await.map_err(sql)?;
            rss_mdm_authorization_service::lock_shared_on(rss_mdm_install_support::StorageProfile::Mdm, &mut tx,proof.tenant_id(),proof.instance_id()).await.map_err(|_|Error::Storage)?;
            let grant=rss_mdm_authorization_service::snapshot_on(rss_mdm_install_support::StorageProfile::Mdm, &mut tx,proof.tenant_id(),proof.instance_id()).await.map_err(|_|Error::Storage)?;
            if grant.query_binding(proof).map_err(|_|Error::Denied)?!=binding {return Err(Error::Conflict);}
            proof.check_live().map_err(|_|Error::Denied)?;
            tx.rollback().await.map_err(sql)?;
            Ok::<_,Error>(())
        }).await;
        match result {
            Ok(Ok(())) => Ok(value),
            other => {
                connection.close_on_drop();
                Err(match other {
                    Ok(Err(e)) => e,
                    Err(_) => deadline(),
                    _ => unreachable!(),
                })
            }
        }
    }
}

fn sql(e: sqlx::Error) -> Error {
    if e.as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|c| c == "40001" || c == "40P01")
    {
        Error::Conflict
    } else {
        Error::Storage
    }
}
