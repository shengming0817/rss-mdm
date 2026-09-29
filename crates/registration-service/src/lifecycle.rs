use crate::Error;
use std::{future::Future, pin::Pin};
/// Participate after registration state is retired, using the same borrowed transaction.
pub trait Retirement: Send + Sync {
    fn retire<'a>(
        &'a self,
        tx: &'a mut sqlx::PgConnection,
        facts: &'a mut Vec<rss_mdm_audit_integration::Fact>,
        tenant: &'a str,
        registration: uuid::Uuid,
        state: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}
pub async fn retire(
    tx: &mut sqlx::PgConnection,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    tenant: &str,
    registration: uuid::Uuid,
    state: &str,
    participant: &dyn Retirement,
) -> Result<(), Error> {
    crate::device::store::retire_state_in(tx, tenant, registration, state).await?;
    participant
        .retire(tx, facts, tenant, registration, state)
        .await
}
