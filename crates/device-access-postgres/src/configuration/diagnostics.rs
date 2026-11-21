//! Configuration delivery credibility is independent of current login-policy qualification.
use super::management::{authorize, fault, tenant};
use crate::{Error, Service, evidence::Authorities};
use rss_mdm_agent_wire::da;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_device_access::configuration::{Resolution, resolve};
use rss_mdm_policy_postgres::device_access as policy;
use rss_mdm_registration_service::device::endpoints;
use rss_mdm_task_trust::configuration::ConfigurationService;
use sqlx::PgConnection;

#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    pub publication: Option<policy::Publication>,
    pub managed_state: da::SourceState,
    pub evidence: Option<da::EvidenceLevel>,
    pub resolution: Resolution,
    pub locked_fields: Vec<da::ConfigurationField>,
    pub artifact: Option<uuid::Uuid>,
    pub reported: Option<da::ApplicationState>,
    pub application: Application,
}

#[derive(serde::Serialize, schemars::JsonSchema, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Application {
    Unknown,
    AwaitingExport,
    Pending,
    OfflinePending,
    Received,
    Rejected,
    VerifiedApplied,
}

fn application_state(
    reported: Option<da::ApplicationState>,
    offline: bool,
    verified: bool,
) -> Application {
    if verified {
        return Application::VerifiedApplied;
    }
    match reported {
        Some(da::ApplicationState::Rejected) => Application::Rejected,
        Some(
            da::ApplicationState::Received
            | da::ApplicationState::Validated
            | da::ApplicationState::Applied,
        ) => Application::Received,
        Some(da::ApplicationState::Unknown) => Application::Unknown,
        None if offline => Application::OfflinePending,
        None => Application::Pending,
    }
}

/// Current issuer authority may release fields through the protected publication operation.
/// Ordinary content/version changes cannot revoke an otherwise valid managed artifact.
async fn fields(
    c: &mut PgConnection,
    config: &da::Configuration,
) -> Result<Vec<da::ConfigurationField>, Error> {
    let current = policy::get_on(c, config.tenant, config.id)
        .await
        .map_err(fault)?
        .ok_or(Error::Corrupt)?;
    Ok(config
        .managed_fields
        .iter()
        .copied()
        .filter(|field| current.managed_fields.contains(field))
        .collect())
}

impl Service {
    pub async fn configuration_diagnostics(
        &self,
        signing: &ConfigurationService,
        authorities: &Authorities,
        p: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<Diagnostics, Error> {
        self.read_with_session(p, (self, signing, authorities, p, device), |ctx, c| Box::pin(async move {
            let (service, signing, authorities, p, device) = *ctx;
            let tenant = tenant(p)?;
            authorize(c, p, &policy::Target::Device { device: *device }, false, false).await?;
            endpoints::lock_da_in(c, p.tenant_id(), device).await?;
            let anchor = endpoints::current_da_in(c, p.tenant_id(), device).await?.ok_or(Error::NotFound)?;
            policy::lock_publications_on(c, tenant).await.map_err(fault)?;
            let publication = policy::selected_on(c, tenant, device).await.map_err(fault)?;
            let now = crate::platform_sso::store::now(c).await?;
            let identity = da::ReportIdentity { service_id: service.service_id()?, tenant,
                device_id: anchor.device,  };

            // Each authority retains bounded references per immutable Policy, even after a
            // complete snapshot omits configuration, reports ordinary delivery, or is revoked.
            let previous: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT mandatory FROM rss_da.deployment_evidence WHERE tenant_id = $1 AND device = $2")
                .bind(tenant).bind(anchor.device.into_uuid())
                .fetch_all(&mut *c).await.map_err(crate::database::db)?;
            let mut locked = Vec::new();
            for value in previous {
                let refs: crate::evidence::Mandatory = serde_json::from_value(value).map_err(|_| Error::Corrupt)?;
                for (policy, fields_by_artifact) in refs {
                  for (field, artifact) in fields_by_artifact {
                    let config = signing.read_on(p.binding(), c, artifact).await?.decode().map_err(|_| Error::Corrupt)?;
                    if config.id != policy || !config.permits(&identity, device)
                        || config.delivery != da::DeliveryPermission::ManagedMandatory
                        || !config.managed_fields.contains(&field) {
                        return Err(Error::Corrupt);
                    }
                    if fields(c, &config).await?.contains(&field) && !locked.contains(&field) { locked.push(field); }
                  }
                }
            }

            let mut state = da::SourceState::Missing;
            let mut readbacks = Vec::new();
            let mut managed = Vec::new();
            let mut evidence = None;
            let observations = authorities.configurations_on(c, p.binding().tenant(), service.service_id()?, &anchor).await;
            match observations {
                Ok(values) => for o in values {
                    let Some(proof) = o.configuration else { continue };
                    let artifact = signing.read_on(p.binding(), c, proof.artifact).await?;
                    let mut config = artifact.decode().map_err(|_| Error::Corrupt)?;
                    if artifact.digest != proof.digest || config.native.digest != proof.native_digest
                        || config.delivery != proof.delivery || config.id != o.policy
                        || !config.permits(&identity, device) {
                        state = da::SourceState::Invalid; break;
                    }
                    if !o.revoked && o.issued_at <= now && now < o.expires_at && proof.state == da::SourceState::Present
                        && publication.as_ref().is_some_and(|p| p.id == o.policy && p.version == o.policy_version)
                        && let Some(readback) = proof.applied
                    {
                        signing.verify_on(c, p.binding().tenant(), &artifact, now).await?;
                        readbacks.push(readback);
                    }
                    if config.delivery != da::DeliveryPermission::ManagedMandatory { continue; }
                    config.managed_fields = fields(c, &config).await?;
                    // A protected release explicitly removes the source's authority.
                    if config.managed_fields.is_empty() { continue; }
                    let issuer = policy::get_on(c, tenant, config.id).await.map_err(fault)?.ok_or(Error::Corrupt)?;
                    if !issuer.enabled || o.revoked { state = da::SourceState::Withdrawn; break; }
                    if o.issued_at > now || config.issued_at > now { state = da::SourceState::Invalid; break; }
                    if o.expires_at <= now || config.expires_at <= now { state = da::SourceState::Expired; break; }
                    if proof.state != da::SourceState::Present { state = proof.state; break; }
                    signing.verify_on(c, p.binding().tenant(), &artifact, now).await?;
                    state = da::SourceState::Present;
                    evidence = Some(da::EvidenceLevel::Verified);
                    managed.push(config);
                },
                Err(Error::Forbidden | Error::Malformed | Error::NotFound) => {
                    if !locked.is_empty() { state = da::SourceState::ReadFailed; }
                }
                Err(e) => return Err(e),
            }
            if state == da::SourceState::Missing && !locked.is_empty() { state = da::SourceState::ReadFailed; }
            if publication.as_ref().is_some_and(|v| !v.enabled) { state = da::SourceState::Withdrawn; }
            let backend = publication.as_ref().filter(|v| v.enabled).map(|v| &v.configuration);
            let candidates: Vec<_> = managed.iter().collect();
            let resolution = resolve(backend, &candidates, state, &locked)?;
            let mut artifact_id = None;
            let mut reported = None;
            let mut application = Application::Unknown;
            if let Some(selected) = publication.as_ref().filter(|v| v.enabled)
                && resolution.blocked.is_none()
            {
                application = Application::AwaitingExport;
                if let Some(signed) = signing.current_on(p.binding(), c, selected.id, selected.revision).await? {
                    let config = signing.verify_on(c, p.binding().tenant(), &signed, now).await?;
                    if !config.permits(&identity, device) || config.version != selected.version || config.id != selected.id
                        || config.delivery != da::DeliveryPermission::Da {
                        return Err(Error::Corrupt);
                    }
                    artifact_id = Some(config.operation_id);
                    let head: Option<serde_json::Value> = sqlx::query_scalar(
                        "SELECT document FROM rss_da.report_heads WHERE tenant_id=$1 AND device=$2 AND kind='application'")
                        .bind(tenant).bind(device.into_uuid()).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
                    if let Some(head) = head {
                        let value: da::ApplicationReport = serde_json::from_value(head).map_err(|_| Error::Corrupt)?;
                        if value.artifact == config.operation_id && value.digest == signed.digest { reported = Some(value.state); }
                    }
                    let seen: Option<i64> = sqlx::query_scalar(
                        "SELECT max((receipt->>'receivedAt')::bigint) FROM rss_da.report_heads WHERE tenant_id=$1 AND device=$2")
                        .bind(tenant).bind(device.into_uuid()).fetch_one(&mut *c).await.map_err(crate::database::db)?;
                    let current: Vec<_> = readbacks.iter().filter(|r| r.backend_artifact == config.operation_id).collect();
                    let verified = !current.is_empty() && current.iter().all(|r| {
                        resolution.configuration.as_ref() == Some(&r.effective)
                            && r.managed_sources.len() == resolution.fields.iter().filter(|f| f.locked).count()
                            && resolution.fields.iter().filter(|f| f.locked).all(|f| {
                                r.managed_sources.get(&f.field).is_some_and(|id| managed.iter().any(|m|
                                    m.operation_id == *id && m.managed_fields.contains(&f.field)))
                            })
                    });
                    let offline = seen.is_some_and(|last| now.saturating_sub(last) >= i64::from(service.report_limits.stale_seconds));
                    application = application_state(reported, offline, verified);
                }
            }
            Ok(Diagnostics { publication, managed_state: state, evidence, resolution, locked_fields: locked, artifact: artifact_id, reported, application })
        })).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn application_requires_an_independent_readback_and_offline_requires_a_watermark() {
        for report in [
            da::ApplicationState::Received,
            da::ApplicationState::Validated,
            da::ApplicationState::Applied,
        ] {
            assert_eq!(
                application_state(Some(report), false, false),
                Application::Received
            );
        }
        assert_eq!(application_state(None, false, false), Application::Pending);
        assert_eq!(
            application_state(None, true, false),
            Application::OfflinePending
        );
        assert_eq!(
            application_state(Some(da::ApplicationState::Unknown), false, false),
            Application::Unknown
        );
        assert_eq!(
            application_state(Some(da::ApplicationState::Rejected), false, false),
            Application::Rejected
        );
        assert_eq!(
            application_state(None, false, true),
            Application::VerifiedApplied
        );
    }
}
