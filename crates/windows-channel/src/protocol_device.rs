//! A protocol locator belongs to the exact frozen enrollment request.
use crate::{Error, database::db};
use rss_mdm_registration_service::DevicePrincipal;
use uuid::Uuid;
pub(crate) async fn on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: Uuid,
    fallback: &str,
) -> Result<String, Error> {
    Ok(sqlx::query_scalar::<_,Option<String>>("SELECT protocol_device FROM mdm_access.enrollment_intents WHERE tenant_id=$1::uuid AND request_id=$2")
        .bind(tenant).bind(request).fetch_optional(c).await.map_err(db)?.flatten().unwrap_or_else(||fallback.to_owned()))
}
pub(crate) async fn read(store: &crate::Store, p: &DevicePrincipal) -> Result<String, Error> {
    let tenant = p.tenant().to_string();
    let mut tx = store.begin_read(&tenant).await?;
    let request =
        crate::enrollment_store::native_request(&mut tx, &tenant, p.device(), p.protocol_request())
            .await
            .map_err(db)?;
    on(&mut tx, &tenant, request, p.device()).await
}
