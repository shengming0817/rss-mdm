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
    // The caller owns the device/channel lock; parent before children is the common order.
    let children = sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND parent_id=$2 AND state='active' ORDER BY id FOR UPDATE")
        .bind(tenant).bind(registration).fetch_all(&mut *tx).await.map_err(crate::database::db)?;
    crate::device::store::retire_state_in(tx, tenant, registration, state).await?;
    for child in children {
        crate::device::store::retire_state_in(tx, tenant, child, state).await?;
        participant.retire(tx, facts, tenant, child, state).await?;
    }
    participant
        .retire(tx, facts, tenant, registration, state)
        .await
}
