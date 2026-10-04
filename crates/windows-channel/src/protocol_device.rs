//! The certificate resolves the registration; its frozen terminal identifier is descriptive.
use crate::{Error, database::db};
use rss_mdm_registration_service::DevicePrincipal;
use uuid::Uuid;
pub(crate) async fn on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registration: Uuid,
    fallback: &str,
) -> Result<String, Error> {
    Ok(sqlx::query_scalar::<_,Option<String>>("SELECT protocol_device FROM mdm_access.enrollment_intents WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(tenant).bind(registration).fetch_optional(c).await.map_err(db)?.flatten().unwrap_or_else(|| fallback.to_owned()))
}
pub(crate) async fn read(store: &crate::Store, p: &DevicePrincipal) -> Result<String, Error> {
    let mut tx = store.begin_read(&p.tenant().to_string()).await?;
    on(
        &mut tx,
        &p.tenant().to_string(),
        p.registration(),
        p.device(),
    )
    .await
}
