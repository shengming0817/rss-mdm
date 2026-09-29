use crate::{Error, database::db};
use rss_mdm_flow_service::execution::channels::{self, AgentBinding, Pending};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub struct Bindings;
impl channels::Agent for Bindings {
    fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registrations: Vec<Uuid>,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, AgentBinding>> {
        Box::pin(async move {
            let rows=sqlx::query("SELECT registration,platform,architecture,capabilities FROM mdm_agent.bindings WHERE tenant_id=$1::uuid AND registration=ANY($2) AND wire_version=3").bind(tenant).bind(registrations).fetch_all(c).await.map_err(|e|channels::Rejection::from(db(e)))?;
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
) -> Result<(), Error> {
    let platform = match platform {
        rss_mdm_agent_wire::TaskPlatform::Windows => "windows",
        rss_mdm_agent_wire::TaskPlatform::Macos => "macos",
    };
    let architecture = match architecture {
        rss_mdm_agent_wire::TaskArchitecture::X86_64 => "x86_64",
        rss_mdm_agent_wire::TaskArchitecture::Aarch64 => "aarch64",
    };
    sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture) VALUES($1::uuid,$2::uuid,3,$3,$4,$5)")
        .bind(tenant).bind(registration.to_string()).bind(capabilities).bind(platform).bind(architecture)
        .execute(&mut *tx).await.map_err(db)?;
    Ok(())
}
