use crate::{Error, database::db};
use rss_mdm_execution_service::channels::{self, AgentBinding, Pending};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub struct Bindings;
impl channels::Agent for Bindings {
    fn update_context<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        registration: Uuid,
        context: &'a rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let row=sqlx::query("SELECT platform,execution_context FROM mdm_agent.bindings WHERE tenant_id=$1::uuid AND registration=$2 FOR UPDATE").bind(&tenant).bind(registration).fetch_optional(&mut *c).await.map_err(|e|channels::Rejection::from(db(e)))?.ok_or(channels::Rejection::Unauthorized)?;
            let platform = match row
                .try_get::<String, _>("platform")
                .map_err(|e| channels::Rejection::from(db(e)))?
                .as_str()
            {
                "windows" => rss_mdm_agent_wire::runtime::TaskPlatform::Windows,
                "macos" => rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
                _ => return Err(channels::Rejection::Protocol),
            };
            context
                .validate_for(platform)
                .map_err(|_| channels::Rejection::Malformed)?;
            let previous: rss_mdm_agent_wire::runtime::SoftwareExecutionContext =
                serde_json::from_value(
                    row.try_get("execution_context")
                        .map_err(|e| channels::Rejection::from(db(e)))?,
                )
                .map_err(|_| channels::Rejection::Protocol)?;
            validate_context_update(context, &previous)?;
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
            let rows=sqlx::query("SELECT registration,platform,architecture,capabilities,execution_context FROM mdm_agent.bindings WHERE tenant_id=$1::uuid AND registration=ANY($2) AND wire_version=1").bind(tenant).bind(registrations).fetch_all(c).await.map_err(|e|channels::Rejection::from(db(e)))?;
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
    platform: rss_mdm_agent_wire::runtime::TaskPlatform,
    architecture: rss_mdm_agent_wire::runtime::TaskArchitecture,
    context: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
) -> Result<(), Error> {
    context
        .validate_for(platform)
        .map_err(|_| Error::Malformed)?;
    let context = serde_json::to_value(context).map_err(|_| Error::Malformed)?;
    let platform = match platform {
        rss_mdm_agent_wire::runtime::TaskPlatform::Windows => "windows",
        rss_mdm_agent_wire::runtime::TaskPlatform::Macos => "macos",
    };
    let architecture = match architecture {
        rss_mdm_agent_wire::runtime::TaskArchitecture::X86_64 => "x86_64",
        rss_mdm_agent_wire::runtime::TaskArchitecture::Aarch64 => "aarch64",
    };
    sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context) VALUES($1::uuid,$2::uuid,1,$3,$4,$5,$6)")
        .bind(tenant).bind(registration.to_string()).bind(capabilities).bind(platform).bind(architecture).bind(context)
        .execute(&mut *tx).await.map_err(db)?;
    Ok(())
}

impl rss_mdm_registration_service::agent::RuntimeBinding for Bindings {
    fn bind<'a>(
        &'a self,
        c: &'a mut PgConnection,
        b: rss_mdm_registration_service::agent::Binding,
        p: &'a rss_mdm_agent_wire::enroll::RuntimeProfile,
    ) -> rss_mdm_registration_service::agent::Pending<'a, rss_mdm_agent_wire::runtime::BindingProfile>
    {
        Box::pin(async move {
            bind_agent_in(
                c,
                &b.tenant.to_string(),
                b.registration,
                &serde_json::to_string(&p.capabilities)
                    .map_err(|_| rss_mdm_registration_service::Error::Malformed)?,
                p.platform,
                p.architecture,
                &p.execution_context,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Storage)?;
            let collections = crate::builtin_collections(c, b.tenant, b.registration, b.epoch)
                .await
                .map_err(|_| rss_mdm_registration_service::Error::Storage)?;
            Ok(rss_mdm_agent_wire::runtime::BindingProfile {
                wire_version: 1,
                operation_id: b.operation,
                device_id: b.device,
                registration_id: b.registration,
                generation: b
                    .generation
                    .try_into()
                    .map_err(|_| rss_mdm_registration_service::Error::Corrupt)?,
                source: rss_mdm_agent_wire::runtime::ReportSource::AgentBuiltin,
                epoch: b.epoch,
                capabilities: p.capabilities.clone(),
                collections,
            })
        })
    }
}

fn validate_context_update(
    context: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    previous: &rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
) -> Result<(), channels::Rejection> {
    if context.revision < previous.revision
        || (context.revision == previous.revision && context != previous)
    {
        Err(channels::Rejection::Conflict)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    fn context() -> rss_mdm_agent_wire::runtime::SoftwareExecutionContext {
        serde_json::from_value(serde_json::json!({"revision":1,"osVersion":[14,0,0,0],"userHelper":true,"systemBroker":true,"interactiveUser":{"generatedUid":"00000000-0000-0000-0000-000000000501","identity":"501","sessionId":Uuid::new_v4(),"administrator":false},"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false})).unwrap()
    }
    #[test]
    fn context_updates_cannot_reuse_a_revision_or_restore_a_previous_login() {
        let first = context();
        let mut next = first.clone();
        next.revision = 2;
        next.interactive_user.as_mut().unwrap().session_id = Uuid::new_v4();
        assert!(validate_context_update(&next, &first).is_ok());
        assert!(validate_context_update(&first, &next).is_err());
        let mut reused = next.clone();
        reused.interactive_user.as_mut().unwrap().session_id = Uuid::new_v4();
        assert!(validate_context_update(&reused, &next).is_err());
        assert!(validate_context_update(&next, &next).is_ok());
    }
}
