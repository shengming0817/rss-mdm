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
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    pub publication: Option<policy::Publication>,
    pub managed_state: da::SourceState,
    pub evidence: Option<da::EvidenceLevel>,
    pub resolution: Resolution,
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
        device: &str,
    ) -> Result<Diagnostics, Error> {
        self.read_with_session(p, (self, signing, authorities, p, device), |ctx, c| Box::pin(async move {
            let (service, signing, authorities, p, device) = *ctx;
            let tenant = tenant(p)?;
            authorize(c, p, &policy::Target::Device { device: device.into() }, false, false).await?;
            endpoints::lock_da_in(c, p.tenant_id(), device).await?;
            let anchor = endpoints::current_da_in(c, p.tenant_id(), device).await?.ok_or(Error::NotFound)?;
            policy::lock_publications_on(c, tenant).await.map_err(fault)?;
            let publication = policy::selected_on(c, tenant, device).await.map_err(fault)?;
            let now = crate::platform_sso::store::now(c).await?;
            let identity = da::ReportIdentity { service_id: service.service_id()?, tenant,
                registration: anchor.registration_id, generation: anchor.generation };

            // Each authority retains bounded references per immutable Policy, even after a
            // complete snapshot omits configuration, reports ordinary delivery, or is revoked.
            let previous: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT mandatory FROM rss_da.deployment_evidence WHERE tenant_id=$1 AND registration=$2 AND generation=$3")
                .bind(tenant).bind(anchor.registration_id).bind(anchor.generation)
                .fetch_all(&mut *c).await.map_err(crate::database::db)?;
            let mut locked = Vec::new();
            for value in previous {
                let refs: BTreeMap<Uuid, Uuid> = serde_json::from_value(value).map_err(|_| Error::Corrupt)?;
                for (policy, artifact) in refs {
                    let config = signing.read_on(c, artifact).await?.decode().map_err(|_| Error::Corrupt)?;
                    if config.id != policy || !config.permits(&identity, device)
                        || config.delivery != da::DeliveryPermission::ManagedMandatory {
                        return Err(Error::Corrupt);
                    }
                    for field in fields(c, &config).await? {
                        if !locked.contains(&field) { locked.push(field); }
                    }
                }
            }

            let mut state = da::SourceState::Missing;
            let mut managed = Vec::new();
            let mut evidence = None;
            let observations = authorities.configurations_on(c, service.tenant, service.service_id()?, &anchor).await;
            match observations {
                Ok(values) => for o in values {
                    let Some(proof) = o.configuration else { continue };
                    let artifact = signing.read_on(c, proof.artifact).await?;
                    let mut config = artifact.decode().map_err(|_| Error::Corrupt)?;
                    if artifact.digest != proof.digest || config.native.digest != proof.native_digest
                        || config.delivery != proof.delivery || config.id != o.policy
                        || !config.permits(&identity, device) {
                        state = da::SourceState::Invalid; break;
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
            Ok(Diagnostics { publication, managed_state: state, evidence, resolution })
        })).await
    }
}
