//! Cross-capability retirement keeps the original transaction and lock order.
use crate::Error;
pub(crate) async fn retire(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    registration: uuid::Uuid,
    state: &str,
) -> Result<(), Error> {
    crate::device::store::retire_state_in(tx, tenant, registration, state).await?;
    crate::apple::retire_in(tx, tenant, registration).await?;
    crate::collection::terminate(tx, tenant, &registration.to_string(), state).await
}
