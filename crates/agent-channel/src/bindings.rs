use crate::{Error, database::db};
use rss_mdm_flow_service::execution::channels::{self, AgentBinding, Pending};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub struct Bindings;
impl channels::Agent for Bindings {
    fn managed_replay<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a crate::device::DevicePrincipal,
        input: &'a rss_mdm_agent_wire::ManagedRegistrationRequest,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> Pending<'a, Option<rss_mdm_agent_wire::RegistrationReceipt>> {
        Box::pin(async move {
            crate::managed::replay(c, p, input, audit)
                .await
                .map_err(Into::into)
        })
    }
    fn managed_register<'a>(
        &'a self,
        c: &'a mut PgConnection,
        authority: rss_mdm_registration_service::enrollment::managed::Authority,
        input: &'a rss_mdm_agent_wire::ManagedRegistrationRequest,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> Pending<'a, rss_mdm_agent_wire::RegistrationReceipt> {
        Box::pin(async move {
            crate::managed::register(c, authority, input, audit)
                .await
                .map_err(Into::into)
        })
    }

    fn update_context<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        context: &'a rss_mdm_agent_wire::SoftwareExecutionContext,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let row=sqlx::query("SELECT platform,execution_context FROM mdm_agent.bindings WHERE tenant_id=$1::uuid AND registration=$2 FOR UPDATE").bind(&tenant).bind(registration).fetch_optional(&mut *c).await.map_err(|e|channels::Rejection::from(db(e)))?.ok_or(channels::Rejection::Unauthorized)?;
            let platform = match row
                .try_get::<String, _>("platform")
                .map_err(|e| channels::Rejection::from(db(e)))?
                .as_str()
            {
                "windows" => rss_mdm_agent_wire::TaskPlatform::Windows,
                "macos" => rss_mdm_agent_wire::TaskPlatform::Macos,
                _ => return Err(channels::Rejection::Protocol),
            };
            context
                .validate_for(platform)
                .map_err(|_| channels::Rejection::Malformed)?;
            let previous: rss_mdm_agent_wire::SoftwareExecutionContext = serde_json::from_value(
                row.try_get("execution_context")
                    .map_err(|e| channels::Rejection::from(db(e)))?,
            )
            .map_err(|_| channels::Rejection::Protocol)?;
            context
                .validate_update(&previous)
                .map_err(|_| channels::Rejection::Conflict)?;
            if context.revision > previous.revision {
                let value =
                    serde_json::to_value(context).map_err(|_| channels::Rejection::Malformed)?;
                sqlx::query("UPDATE mdm_agent.bindings SET execution_context=$3 WHERE tenant_id=$1::uuid AND registration=$2").bind(tenant).bind(registration).bind(value).execute(c).await.map_err(|e|channels::Rejection::from(db(e)))?;
            }
            Ok(())
        })
    }
    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registrations: Vec<Uuid>,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, AgentBinding>> {
        Box::pin(async move {
            let rows=sqlx::query("SELECT registration,platform,architecture,capabilities,execution_context FROM mdm_agent.bindings WHERE tenant_id=$1::uuid AND registration=ANY($2) AND wire_version=5").bind(tenant).bind(registrations).fetch_all(c).await.map_err(|e|channels::Rejection::from(db(e)))?;
            rows.into_iter()
                .map(|r| {
                    let value = |key: &str| {
                        r.try_get::<String, _>(key)
                            .map_err(|e| channels::Rejection::from(db(e)))
                    };
                    Ok((
                        r.try_get("registration")
                            .map_err(|e| channels::Rejection::from(db(e)))?,
                        AgentBinding {
                            execution_context: serde_json::from_value(
                                r.try_get("execution_context")
                                    .map_err(|e| channels::Rejection::from(db(e)))?,
                            )
                            .map_err(|_| channels::Rejection::Protocol)?,
                            platform: value("platform")?,
                            architecture: value("architecture")?,
                            capabilities: serde_json::from_str(&value("capabilities")?)
                                .map_err(|_| channels::Rejection::Protocol)?,
                        },
                    ))
                })
                .collect()
        })
    }
}
pub(crate) async fn inventory_in(
    c: &mut PgConnection,
    p: &crate::device::DevicePrincipal,
) -> Result<(), Error> {
    use channels::Agent;
    if !Bindings
        .binding(c, p.tenant().to_string(), p.registration())
        .await?
        .is_some_and(|b| b.inventory())
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub(crate) async fn bind_agent_in(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    registration: Uuid,
    capabilities: &str,
    platform: rss_mdm_agent_wire::TaskPlatform,
    architecture: rss_mdm_agent_wire::TaskArchitecture,
    context: &rss_mdm_agent_wire::SoftwareExecutionContext,
) -> Result<(), Error> {
    context
        .validate_for(platform)
        .map_err(|_| Error::Malformed)?;
    let context = serde_json::to_value(context).map_err(|_| Error::Malformed)?;
    let platform = match platform {
        rss_mdm_agent_wire::TaskPlatform::Windows => "windows",
        rss_mdm_agent_wire::TaskPlatform::Macos => "macos",
    };
    let architecture = match architecture {
        rss_mdm_agent_wire::TaskArchitecture::X86_64 => "x86_64",
        rss_mdm_agent_wire::TaskArchitecture::Aarch64 => "aarch64",
    };
    sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context) VALUES($1::uuid,$2::uuid,5,$3,$4,$5,$6)")
        .bind(tenant).bind(registration.to_string()).bind(capabilities).bind(platform).bind(architecture).bind(context)
        .execute(&mut *tx).await.map_err(db)?;
    Ok(())
}
