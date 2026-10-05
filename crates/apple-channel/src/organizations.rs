//! Apple channel owns one organization identity; protocol configurations are independent.
use crate::{Error, database::db};
use sqlx::PgConnection;
use uuid::Uuid;

pub(crate) async fn ensure_in(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<(), Error> {
    if id.is_nil() {
        return Err(Error::Malformed);
    }
    sqlx::query("INSERT INTO mdm_apple.organizations(tenant_id,id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING")
        .bind(tenant).bind(id).execute(c).await.map_err(db)?;
    Ok(())
}
