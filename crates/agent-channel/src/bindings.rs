use crate::binding_facts::{Binding, Pending};
use crate::{Error, database::db};
use sqlx::{PgConnection, Row};
pub struct Bindings {
    profile: rss_mdm_install_support::StorageProfile,
}
impl Bindings {
    pub const fn new(profile: rss_mdm_install_support::StorageProfile) -> Self {
        Self { profile }
    }
    pub const fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    pub fn update_context<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: rss_mdm_agent_wire::DeviceId,
        context: &'a rss_mdm_agent_wire::runtime::SoftwareExecutionContext,
    ) -> Pending<'a, ()> {
        let profile = self.profile();

        Box::pin(async move {
            let row = sqlx::query(crate::storage_profile::sql(profile).bindings_update_context_1)
                .bind(&tenant)
                .bind(device.into_uuid())
                .fetch_optional(&mut *c)
                .await
                .map_err(db)?
                .ok_or(Error::Unauthorized)?;
            let platform = match row.try_get::<String, _>("platform").map_err(db)?.as_str() {
                "windows" => rss_mdm_agent_wire::runtime::TaskPlatform::Windows,
                "macos" => rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
                _ => return Err(Error::Unavailable(crate::Failure::Protocol)),
            };
            context
                .validate_for(platform)
                .map_err(|_| Error::Malformed)?;
            let previous: rss_mdm_agent_wire::runtime::SoftwareExecutionContext =
                serde_json::from_value(row.try_get("execution_context").map_err(db)?)
                    .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?;
            validate_context_update(context, &previous)?;
            if context.revision > previous.revision {
                let value = serde_json::to_value(context).map_err(|_| Error::Malformed)?;
                sqlx::query(crate::storage_profile::sql(profile).bindings_update_context_2)
                    .bind(tenant)
                    .bind(device.into_uuid())
                    .bind(value)
                    .execute(c)
                    .await
                    .map_err(db)?;
            }
            Ok(())
        })
    }
    pub fn binding<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, Option<Binding>> {
        Box::pin(async move {
            Ok(self
                .bindings(c, tenant, vec![device])
                .await?
                .remove(&device))
        })
    }
    pub fn announcement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: rss_mdm_agent_wire::DeviceId,
    ) -> Pending<'a, Option<rss_mdm_agent_wire::runtime::TaskClaimRequest>> {
        let profile = self.profile();

        Box::pin(async move {
            let value: Option<serde_json::Value> =
                sqlx::query_scalar(crate::storage_profile::sql(profile).bindings_announcement_1)
                    .bind(tenant)
                    .bind(device.into_uuid())
                    .fetch_optional(c)
                    .await
                    .map_err(db)?
                    .flatten();
            value
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| Error::Unavailable(crate::Failure::Protocol))
        })
    }
    pub fn announce<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        device: rss_mdm_agent_wire::DeviceId,
        input: &'a rss_mdm_agent_wire::runtime::TaskClaimRequest,
    ) -> Pending<'a, ()> {
        let profile = self.profile();

        Box::pin(async move {
            let value = serde_json::to_value(input).map_err(|_| Error::Malformed)?;
            let n = sqlx::query(crate::storage_profile::sql(profile).bindings_announce_1)
                .bind(tenant)
                .bind(device.into_uuid())
                .bind(value)
                .execute(c)
                .await
                .map_err(db)?
                .rows_affected();
            if n != 1 {
                return Err(Error::Unauthorized);
            }
            Ok(())
        })
    }
    pub fn bindings<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        devices: Vec<rss_mdm_agent_wire::DeviceId>,
    ) -> Pending<'a, std::collections::BTreeMap<rss_mdm_agent_wire::DeviceId, Binding>> {
        let profile = self.profile();

        Box::pin(async move {
            let rows = sqlx::query(crate::storage_profile::sql(profile).bindings_bindings_1)
                .bind(tenant)
                .bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
                .fetch_all(c)
                .await
                .map_err(db)?;
            rows.into_iter()
                .map(|r| {
                    let value = |key: &str| r.try_get::<String, _>(key).map_err(db);
                    Ok((
                        r.try_get::<uuid::Uuid, _>("device")
                            .and_then(|id| {
                                rss_mdm_agent_wire::DeviceId::try_from(id)
                                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))
                            })
                            .map_err(db)?,
                        Binding {
                            execution_context: serde_json::from_value(
                                r.try_get("execution_context").map_err(db)?,
                            )
                            .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?,
                            platform: value("platform")?,
                            architecture: value("architecture")?,
                            capabilities: serde_json::from_str(&value("capabilities")?)
                                .map_err(|_| Error::Unavailable(crate::Failure::Protocol))?,
                        },
                    ))
                })
                .collect()
        })
    }
}
pub(crate) async fn inventory_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &crate::device::DevicePrincipal,
) -> Result<(), Error> {
    if !Bindings::new(profile)
        .binding(c, p.tenant().to_string(), p.device().to_owned())
        .await?
        .is_some_and(|b| b.inventory())
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
#[allow(
    clippy::too_many_arguments,
    reason = "original enrollment transaction persists explicit product, device and negotiated Agent facts"
)]
pub(crate) async fn bind_agent_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    device: rss_mdm_agent_wire::DeviceId,
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
    sqlx::query(crate::storage_profile::sql(profile).bindings_bind_agent_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(capabilities)
        .bind(platform)
        .bind(architecture)
        .bind(context)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    Ok(())
}

impl rss_mdm_registration_service::agent::RuntimeBinding for Bindings {
    fn storage_profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.profile
    }
    fn bind<'a>(
        &'a self,
        c: &'a mut PgConnection,
        b: rss_mdm_registration_service::agent::Binding,
        p: &'a rss_mdm_agent_wire::enroll::RuntimeProfile,
    ) -> rss_mdm_registration_service::agent::Pending<'a, rss_mdm_agent_wire::runtime::BindingProfile>
    {
        let profile = self.profile();

        Box::pin(async move {
            if b.profile != self.profile {
                return Err(rss_mdm_registration_service::Error::Forbidden);
            }
            bind_agent_in(
                profile,
                c,
                &b.tenant.to_string(),
                b.device,
                &serde_json::to_string(&p.capabilities)
                    .map_err(|_| rss_mdm_registration_service::Error::Malformed)?,
                p.platform,
                p.architecture,
                &p.execution_context,
            )
            .await
            .map_err(|_| rss_mdm_registration_service::Error::Storage)?;
            let collections = crate::builtin_collections(profile, c, b.tenant, &b.device, b.epoch)
                .await
                .map_err(|_| rss_mdm_registration_service::Error::Storage)?;
            Ok(rss_mdm_agent_wire::runtime::BindingProfile {
                wire_version: 1,
                operation_id: b.operation,
                device_id: b.device,

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
) -> Result<(), Error> {
    if context.revision < previous.revision
        || (context.revision == previous.revision && context != previous)
    {
        Err(Error::Conflict)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    fn context() -> rss_mdm_agent_wire::runtime::SoftwareExecutionContext {
        serde_json::from_value(serde_json::json!({"revision":1,"osVersion":[14,0,0,0],"userHelper":true,"systemBroker":true,"interactiveUser":{"windowsAuthority":null,"generatedUid":"00000000-0000-0000-0000-000000000501","identity":"501","sessionId":Uuid::new_v4(),"administrator":false},"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false})).unwrap()
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
