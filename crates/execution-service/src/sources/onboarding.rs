//! Management diagnosis reads the same source facts and frozen grants as onboarding execution.
use super::*;
use rss_mdm_inventory::ReportSource;
use software::{TaskAdmission, TaskAdmissionState as State};

pub async fn state_in(
    service: &crate::ExecutionService,
    tx: &mut PgTransaction<'_>,
    device: &str,
    frozen: &Frozen,
) -> Result<TaskAdmission> {
    let now = crate::storage::now(tx).await?;
    let (schedule, channel) = match frozen {
        Frozen::AgentInstall { action } => (&action.schedule, "mdm"),
        Frozen::MdmEnrollment { action } => (&action.schedule, "agent"),
        _ => return Err(Error::Malformed.into()),
    };
    let status = |state| Ok(TaskAdmission::new(state, None));
    if now < schedule.not_before || now >= schedule.ends_at() {
        return status(State::OutsideWindow);
    }
    let grants = match frozen {
        Frozen::AgentInstall { action } => vec![
            (action.deploy.clone(), Permission::SoftwareDeploy),
            (action.enrollment.clone(), Permission::Enrollment),
        ],
        Frozen::MdmEnrollment { action } => vec![(action.grant.clone(), Permission::Enrollment)],
        _ => unreachable!(),
    };
    for (grant, permission) in grants {
        if !tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(grant.valid(c, permission, now).await) })
            })
            .await??
        {
            return status(State::PermissionWithdrawn);
        }
    }
    let tenant = tx.tenant_id();
    let name = device.to_owned();
    let rows=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as::<_,(Uuid,i64,String)>("SELECT r.id,r.generation,s.source FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel=$3 AND r.state='active' AND s.enabled AND s.source IN('mdm.windows','mdm.apple','agent.builtin')")
            .bind(tenant.to_string()).bind(name).bind(channel).fetch_all(c).await
    })).await?;
    if rows.is_empty() {
        return status(State::MissingRegistration);
    }
    if rows.len() != 1 {
        return status(State::AmbiguousRegistration);
    }
    let (registration, generation, source) = &rows[0];
    let registration = *registration;
    let generation = *generation;
    let source = match source.as_str() {
        "mdm.windows" => ReportSource::MdmWindows,
        "mdm.apple" => ReportSource::MdmApple,
        "agent.builtin" => ReportSource::AgentBuiltin,
        _ => return Err(Error::Malformed.into()),
    };
    let fact = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(
                    crate::assets::channel::detail_in(c, tenant, registration, generation, source)
                        .await,
                )
            })
        })
        .await??;
    if source == ReportSource::MdmApple {
        let rights=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,bool>("SELECT access_rights & 4352 = 4352 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(tenant.to_string()).bind(registration).fetch_optional(c).await
        })).await?.unwrap_or(false);
        if !rights {
            return status(State::MissingNativeRights);
        }
    }
    let Some(fact) = fact else {
        return status(State::ChannelUnknown);
    };
    match frozen {
        Frozen::AgentInstall { action } => {
            match fact.state.as_str() {
                "installed" if source == ReportSource::MdmWindows => {
                    return status(State::AlreadySatisfied);
                }
                "absent" => (),
                _ => return status(State::ChannelUnknown),
            }
            let Some(evidence) = fact.evidence else {
                return status(State::ChannelUnknown);
            };
            let architecture = match evidence.architecture.as_deref() {
                Some("x86_64") => Architecture::X86_64,
                Some("aarch64") => Architecture::Aarch64,
                _ => return status(State::MissingArchitecture),
            };
            let platform = match source {
                ReportSource::MdmWindows => Platform::Windows,
                ReportSource::MdmApple => Platform::Macos,
                _ => return status(State::MissingRegistration),
            };
            let target = rss_mdm_policy::SoftwareTarget::new(platform, architecture);
            let Some(package) = action.packages.get(&target) else {
                return status(State::MissingVariant);
            };
            let Some(pin) = service.agent_installation.packages.get(&target) else {
                return status(State::MissingVariant);
            };
            let identity = match &package.identity {
                crate::agent_install::Identity::Windows { product, .. } => product.to_string(),
                crate::agent_install::Identity::Macos { bundle, .. } => bundle.clone(),
            };
            if identity != evidence.identity
                || package.identity != pin.identity
                || package.artifact.sha256 != pin.sha256
                || package.version != pin.version
            {
                return status(State::MissingVariant);
            }
            let action = action.clone();
            let approved = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(rss_mdm_software_service::catalog::admitted_on(
                            c,
                            tenant,
                            action.resource.id(),
                            action.resource.version(),
                            action.resource_digest,
                            action.admission_operation,
                            &action
                                .packages
                                .values()
                                .map(|p| p.source.clone())
                                .collect::<Vec<_>>(),
                        )
                        .await)
                    })
                })
                .await??;
            if !approved {
                return status(State::ApprovalWithdrawn);
            }
        }
        Frozen::MdmEnrollment { action } => {
            match fact.state.as_str() {
                "this_organization" => return status(State::AlreadySatisfied),
                "other_organization" => return status(State::OrganizationConflict),
                "unenrolled" => (),
                _ => return status(State::ChannelUnknown),
            }
            let Some(binding) =
                crate::channels::agent_binding_in(tx, service.agent_store.clone(), registration)
                    .await?
            else {
                return status(State::MissingRegistration);
            };
            if !binding.enrollment() {
                return status(State::UnsupportedCapability);
            }
            if match binding.platform.as_str() {
                "windows" => action.entries.windows.is_none(),
                "macos" => action.entries.macos.is_none(),
                _ => true,
            } {
                return status(State::MissingVariant);
            }
        }
        _ => unreachable!(),
    }
    status(State::Eligible)
}
