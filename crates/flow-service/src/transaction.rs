//! Transaction context used only by the remaining source-change scanner.
use crate::Error;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
#[derive(Debug, thiserror::Error)]
pub(crate) enum Fault {
    #[error(transparent)]
    Request(#[from] Error),
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}
pub(crate) type Result<T> = std::result::Result<T, Fault>;
pub fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(6),
    )
}
pub(crate) async fn lock(tx: &mut PgTransaction<'_>) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let directory_tenant = tenant.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            rss_mdm_registration_service::lifecycle::lock_write_watermarks_in(c, &tenant).await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2390))")
                .bind(tenant)
                .execute(&mut *c)
                .await?;
            sqlx::query("SELECT mdm_devices.lock_query_revision($1::uuid)")
                .bind(directory_tenant)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}

impl From<rss_mdm_execution_service::transaction::Fault> for Fault {
    fn from(e: rss_mdm_execution_service::transaction::Fault) -> Self {
        use rss_mdm_execution_service::transaction::Fault as F;
        match e {
            F::Request(e) => Self::Request(e.into()),
            F::Storage(e) => Self::Storage(e),
            F::Sql(e) => Self::Sql(e),
        }
    }
}
