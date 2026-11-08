//! Qualification consumes DA-owned, cryptographically verified deployment evidence.
use super::*;
use rss_mdm_registration_service::device::endpoints::DaRegistration;
use sqlx::PgConnection;
use uuid::Uuid;
pub async fn ready(
    app: &Context,
    c: &mut PgConnection,
    object: &DaRegistration,
    now: i64,
) -> Result<(), Error> {
    store::current_object(app, c, object).await?;
    let login = configuration_for_object(c, app.tenant, object).await?;
    let rt = app.runtime()?;
    rt.evidence
        .current_on(
            c,
            app.tenant,
            app.installation,
            object,
            &rt.qualification_configuration()?,
            rt.profile(&login)?.uuid,
            now,
        )
        .await?;
    Ok(())
}
pub async fn configuration_for_object(
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
    object: &DaRegistration,
) -> Result<rss_mdm_agent_wire::platform_sso::LoginConfiguration, Error> {
    crate::device_access::storage::mac_configuration_in(
        c,
        Uuid::parse_str(&tenant.to_string()).map_err(|_| Error::Malformed)?,
        &object.device,
    )
    .await
}
