//! Configuration delivery credibility is independent of current login-policy qualification.
use super::management::{authorize, fault, matches_backend, tenant};
use crate::{Error, Service, evidence::Authorities};
use rss_mdm_agent_wire::da;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_device_access::configuration::{Resolution, resolve};
use rss_mdm_policy_postgres::device_access as policy;
use rss_mdm_registration_service::device::endpoints;
use rss_mdm_task_trust::configuration::ConfigurationService;

#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    pub publication: Option<da::Publication>,
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

fn current_readback(observation: (i64, i64), artifact: (i64, i64), now: i64) -> bool {
    [observation, artifact]
        .into_iter()
        .all(|(issued, expires)| issued <= now && now < expires)
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
        _ if offline => Application::OfflinePending,
        Some(
            da::ApplicationState::Received
            | da::ApplicationState::Validated
            | da::ApplicationState::Applied,
        ) => Application::Received,
        Some(da::ApplicationState::Unknown) => Application::Unknown,
        None => Application::Pending,
    }
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
            authorize(c, p, &da::Target::Device { device: *device }, false, false).await?;
            endpoints::lock_da_in(c, p.tenant_id(), device).await?;
            let anchor = endpoints::current_da_in(c, p.tenant_id(), device).await?.ok_or(Error::NotFound)?;
            policy::lock_publications_on(c, tenant).await.map_err(fault)?;
            let issuers = policy::applicable_on(c, tenant, device).await.map_err(fault)?;
            let publication = issuers.first().map(|(p, _)| p.clone());
            let issuer = |id| issuers.iter().find(|(_, a)| a.policy == id).map(|(_, a)| a).ok_or(Error::Corrupt);
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
                  for (field, saved) in fields_by_artifact {
                    let config = signing.read_on(p.binding(), c, saved.artifact).await?.decode().map_err(|_| Error::Corrupt)?;
                    if config.id != policy || config.revision != saved.revision || !config.permits(&identity, device)
                        || config.delivery != da::DeliveryPermission::ManagedMandatory
                        || !config.managed_fields.contains(&field) {
                        return Err(Error::Corrupt);
                    }
                    if issuer(config.id)?.covers_managed_field(&config, field) && !locked.contains(&(policy, field)) { locked.push((policy, field)); }
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
                    if !o.revoked && proof.state == da::SourceState::Present
                        && current_readback((o.issued_at,o.expires_at),(config.issued_at,config.expires_at),now)
                        && let Some(readback) = proof.applied
                        && policy::get_on(c, tenant, o.policy).await.map_err(fault)?.is_some_and(|source| source.enabled && source.version == o.policy_version)
                    {
                        signing.verify_on(c, p.binding().tenant(), &artifact, now).await?;
                        readbacks.push(readback);
                    }
                    if config.delivery != da::DeliveryPermission::ManagedMandatory { continue; }
                    let authority = issuer(config.id)?;
                    config.managed_fields = config.managed_fields.iter().copied().filter(|field| authority.covers_managed_field(&config, *field)).collect();
                    // A protected release explicitly removes the source's authority.
                    if config.managed_fields.is_empty() { continue; }
                    if !authority.enabled || o.revoked { state = da::SourceState::Withdrawn; break; }
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
            if matches!(state, da::SourceState::Present | da::SourceState::Missing)
                && locked.iter().any(|(id, field)| !managed.iter().any(|m| m.id == *id && m.managed_fields.contains(field))) {
                state = da::SourceState::ReadFailed;
            }
            let locked: Vec<_> = [da::ConfigurationField::Mac, da::ConfigurationField::Windows].into_iter()
                .filter(|field| locked.iter().any(|(_, required)| required == field)).collect();
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
                let candidate = async {
                    let Some(signed) = signing.current_on(p.binding(), c, selected.id, selected.revision).await? else {
                        return Ok(None);
                    };
                    let config = signing.verify_on(c, p.binding().tenant(), &signed, now).await?;
                    if !config.permits(&identity, device) || !matches_backend(selected, &config) {
                        return Err(Error::Conflict);
                    }
                    Ok(Some((signed, config)))
                }.await;
                let qualified = match candidate {
                    Ok(None) => { application = Application::AwaitingExport; None }
                    Ok(value) => value,
                    Err(Error::Forbidden | Error::Conflict | Error::Malformed) => None,
                    Err(error) => return Err(error),
                };
                if let Some((signed, config)) = qualified {
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
    fn readback_requires_both_lifetimes() {
        assert!(current_readback((20, 90), (10, 50), 49));
        assert!(!current_readback((20, 90), (10, 50), 50));
        assert!(!current_readback((20, 90), (30, 100), 29));
    }
    #[test]
    fn application_requires_an_independent_readback_and_offline_requires_a_watermark() {
        for report in [
            da::ApplicationState::Received,
            da::ApplicationState::Validated,
            da::ApplicationState::Applied,
        ] {
            assert_eq!(
                application_state(Some(report), true, false),
                Application::OfflinePending
            );
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
