//! A command owner updates its own exact row in the projection's borrowed transaction.
use rss_transactional_messaging::{fence::ExecutionBinding, message::MessageFingerprint};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use uuid::Uuid;

pub const DISCOVERY_SQL: &str = include_str!("command-relay.sql");

pub struct Dispatch {
    pub binding: ExecutionBinding,
    pub id: Uuid,
    pub fingerprint: MessageFingerprint,
}
impl Dispatch {
    /// The statement pins the owner table, current authored epoch and original fingerprint.
    pub async fn accept_in(
        &self,
        tx: &mut PgTransaction<'_>,
        statement: &'static str,
    ) -> Result<bool, PgError> {
        let tenant = tx.tenant_id().to_string();
        let id = self.id;
        let fingerprint = self.fingerprint;
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(sqlx::query(statement)
                    .bind(tenant)
                    .bind(id)
                    .bind(fingerprint.as_bytes().as_slice())
                    .execute(c)
                    .await?
                    .rows_affected()
                    == 1)
            })
        })
        .await
    }

    /// Project the actual native command status for this original dispatch audit fact.
    pub async fn native_status_in(&self, tx: &mut PgTransaction<'_>) -> Result<String, PgError> {
        let id = self.id.to_string();
        let fingerprint = self.fingerprint;
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT public.mdm_dispatch_native_status($1,$2)")
                    .bind(id)
                    .bind(fingerprint.as_bytes().as_slice())
                    .fetch_one(c)
                    .await
            })
        })
        .await
    }
}
