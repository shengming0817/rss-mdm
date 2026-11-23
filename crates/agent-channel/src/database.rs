use crate::{Error, Failure};
use sqlx::{PgPool, Postgres, Transaction};
pub struct Store {
    profile: rss_mdm_install_support::StorageProfile,
    pool: PgPool,
}
impl Store {
    pub fn from_pool(profile: rss_mdm_install_support::StorageProfile, pool: PgPool) -> Self {
        Self { profile, pool }
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub(crate) async fn begin(
        &self,
        tenant: &str,
        control: &rss_axum::RequestControl,
    ) -> Result<Transaction<'_, Postgres>, Error> {
        use rss_request_context::{CancellationObserver, Clock};
        let deadline = control.deadline();
        let timeout = || Error::Unavailable(Failure::RequestDeadline);
        tokio::select! {
            biased;
            () = control.cancelled() => Err(timeout()),
            () = tokio::time::sleep_until(deadline.instant().into()) => Err(timeout()),
            result = async {
                let mut tx = self.pool.begin().await.map_err(db)?;
                let remaining = deadline.remaining(rss_mdm_audit_integration::budget::RuntimeTimer.now()).ok_or_else(timeout)?;
                let millis = remaining.as_millis().clamp(1, i32::MAX as u128).to_string();
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true),set_config('transaction_timeout',$2,true)")
                    .bind(tenant).bind(millis).execute(&mut *tx).await.map_err(db)?;
                Ok(tx)
            } => result,
        }
    }
}
pub(crate) fn db(e: sqlx::Error) -> Error {
    if e.as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|code| matches!(code.as_ref(), "57014" | "55P03" | "25P04"))
    {
        return Error::Unavailable(Failure::RequestDeadline);
    }
    if e.as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|c| c == "40001" || c == "40P01")
    {
        Error::Conflict
    } else {
        Error::Unavailable(Failure::Database)
    }
}

#[cfg(test)]
#[path = "../tests/sql_budget.rs"]
mod budget_t2;
