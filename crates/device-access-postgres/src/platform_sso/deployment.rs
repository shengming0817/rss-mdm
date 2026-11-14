//! Qualification consumes DA-owned, cryptographically verified deployment evidence.
use super::*;
use rss_mdm_registration_service::device::endpoints::DaRegistration;
use sqlx::PgConnection;
use uuid::Uuid;
pub async fn ready(
    execution: rss_transactional_messaging::fence::ExecutionBinding,

    app: &Context,
    c: &mut PgConnection,
    object: &DaRegistration,
    now: i64,
) -> Result<(), Error> {
    store::current_object(execution, c, object).await?;
    let login = configuration_for_object(c, execution.tenant(), object).await?;
    let rt = app.runtime()?;
    rt.evidence
        .current_on(
            c,
            execution.tenant(),
            app.installation,
            object,
            &rt.qualification_configuration()?,
            rt.profile(
                uuid::Uuid::parse_str(&execution.tenant().to_string())
                    .map_err(|_| Error::Malformed)?,
                &login,
            )?
            .uuid,
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
