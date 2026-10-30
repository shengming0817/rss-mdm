//! Management diagnosis reads the same source facts and frozen grants as onboarding execution.
use super::*;
use rss_mdm_inventory::ReportSource;
use software::{TaskAdmission, TaskAdmissionState as State};

pub async fn state_on(
    service: &crate::queries::Admission,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
    frozen: &Frozen,
    version: Uuid,
    now: i64,
) -> Result<TaskAdmission> {
    let (schedule, channel) = match frozen {
        Frozen::AgentInstall { action } => (&action.schedule, "mdm"),
        Frozen::MdmEnrollment { action } => (&action.schedule, "agent"),
        _ => return Err(Error::Malformed.into()),
    };
    let status = |state| Ok(TaskAdmission::new(state, None));
    if now < schedule.not_before || now >= schedule.ends_at() {
        return status(State::OutsideWindow);
    }
    let name = device.to_owned();
    let rows = {
        sqlx::query_as::<_,(Uuid,i64,String)>("SELECT r.id,r.generation,s.source FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel=$3 AND r.state='active' AND s.enabled AND s.source IN('mdm.windows','mdm.apple','agent.builtin')")
            .bind(tenant.to_string()).bind(name).bind(channel).fetch_all(&mut *c).await
    }?;
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
    let fact =
        crate::assets::channel::detail_in(c, tenant, registration, generation, source).await?;
    if source == ReportSource::MdmApple {
        let rights={
            sqlx::query_scalar::<_,bool>("SELECT access_rights & 4352 = 4352 FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2 AND state='active'").bind(tenant.to_string()).bind(registration).fetch_optional(&mut *c).await
        }?.unwrap_or(false);
        if !rights {
            return status(State::MissingNativeRights);
        }
    }
    let fact = match fact {
        crate::assets::channel::Observation::Ready(fact) => fact,
        crate::assets::channel::Observation::ProjectionPending { .. } => {
            return status(State::ProjectionPending);
        }
        crate::assets::channel::Observation::Unavailable => return status(State::ChannelUnknown),
    };
    match frozen {
        Frozen::AgentInstall { action } => {
            let Some(evidence) = &fact.evidence else {
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
            let digest = crate::agent_install::detection_on(c, tenant, source)
                .await?
                .digest()?;
            if evidence.catalog_digest != digest || !evidence.matches(&package.detection_identity())
            {
                return status(State::ChannelUnknown);
            }
            use crate::agent_install::recovery::{self, Gate, Signal};
            let tenant_name = tenant.to_string();
            let contact = recovery::contact_on(c, &tenant_name, registration, generation).await?;
            match recovery::signal(&fact, package, &contact, now) {
                Signal::Healthy => return status(State::AlreadySatisfied),
                Signal::Unknown => return status(State::ChannelUnknown),
                Signal::Absent | Signal::Unresponsive => (),
            }
            let tenant_name = tenant.to_string();
            let snapshot = fact.snapshot;
            let last_contact = contact.last;
            let gate = recovery::gate_on(
                c,
                &tenant_name,
                (registration, generation, version),
                snapshot,
                last_contact,
                now,
            )
            .await?;
            match gate {
                Gate::Ready => (),
                Gate::Pending(_) => return status(State::InstallationPending),
                Gate::ObservationPending => return status(State::RecoveryObservationPending),
                Gate::Exhausted => return status(State::RecoveryRetryExhausted),
            }
            let authorized = package.admitted_snapshot_on(c, tenant).await?;
            if !authorized {
                return status(State::AuthorizationWithdrawn);
            }
        }
        Frozen::MdmEnrollment { action } => {
            match fact.state.as_str() {
                "this_organization" => return status(State::AlreadySatisfied),
                "other_organization" => return status(State::OrganizationConflict),
                "unenrolled" => (),
                _ => return status(State::ChannelUnknown),
            }
            let Some(binding) = crate::channels::agent_binding_on(
                c,
                tenant,
                service.agent_store.clone(),
                registration,
            )
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
