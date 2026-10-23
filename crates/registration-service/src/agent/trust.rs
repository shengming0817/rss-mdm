//! Public bootstrap trust uses the fixed HTTPS authority; installation ACK requires a live device credential.
use super::*;
use rss_mdm_agent_wire::pki::{Acknowledgement, Trust};
use rss_mdm_certificate::ClientCertificateEvidence;
impl Service {
    pub async fn device_trust(
        &self,
        peer: Option<&ClientCertificateEvidence>,
    ) -> Result<Trust, Failure> {
        if let Some(peer) = peer {
            self.authenticate(peer).await?;
        }
        self.trust()
            .trust
            .public()
            .map_err(|_| Error::Corrupt.into())
    }
    pub async fn acknowledge_trust(
        &self,
        peer: &ClientCertificateEvidence,
        input: &Acknowledgement,
        a: &RequestAudit,
    ) -> Result<(), Failure> {
        input.validate().map_err(|_| Error::Malformed)?;
        let p = self.authenticate(peer).await?;
        a.identify_device(p.registration());
        a.target(p.device());
        a.operation(input.operation, "agent_trust_acknowledge");
        let trust = self.trust().trust.public().map_err(|_| Error::Corrupt)?;
        let d = digest(&(p.registration(), input))?;
        self.write(a, (self, p, input, trust, d, a), |ctx, c| {
            Box::pin(async move {
                let (service, p, input, trust, d, a) = ctx;
                crate::device::store::revalidate_source(
                    c,
                    p,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await?;
                let tenant = service.tenant.to_string();
                let actor = p.registration().to_string();
                let hash = Sha256::digest(d.as_bytes()).to_vec();
                let replay = rss_mdm_pki_service::mutation::replay(
                    c,
                    &tenant,
                    &actor,
                    "",
                    input.operation,
                    "trust_acknowledge",
                    &hash,
                )
                .await
                .map_err(|_| Error::Conflict)?
                .is_some();
                if replay {
                    return Ok(Change {
                        value: (),
                        replay: true,
                        digest: d.clone(),
                    });
                }
                rss_mdm_pki_service::registry::Registry::acknowledge_in(
                    c,
                    &service.tenant.to_string(),
                    p.registration(),
                    trust,
                    input,
                )
                .await
                .map_err(|e| match e {
                    rss_mdm_pki_service::Error::Conflict => Error::Conflict,
                    _ => Error::Storage,
                })?;
                rss_mdm_pki_service::mutation::save(
                    c,
                    (&tenant, &actor, ""),
                    input.operation,
                    "trust_acknowledge",
                    &hash,
                    b"null",
                )
                .await
                .map_err(|_| Error::Storage)?;
                let _ = a;
                Ok(Change {
                    value: (),
                    replay: false,
                    digest: d.clone(),
                })
            })
        })
        .await
        .map_err(Into::into)
    }
}

impl Service {
    pub async fn observe_trust(
        &self,
        peer: &ClientCertificateEvidence,
        input: &rss_mdm_agent_wire::pki::Observation,
        a: &RequestAudit,
    ) -> Result<(), Failure> {
        input.validate().map_err(|_| Error::Malformed)?;
        let p = self.authenticate(peer).await?;
        if input.registration != p.registration() || input.generation != p.generation() as u64 {
            return Err(Error::Forbidden.into());
        }
        a.identify_device(p.registration());
        a.target(p.device());
        a.operation(input.operation, "agent_trust_observe");
        let d = digest(&(p.registration(), input))?;
        self.write(a, (self, p, input, d), |ctx, c| {
            Box::pin(async move {
                let (service, p, input, d) = ctx;
                crate::device::store::revalidate_source(
                    c,
                    p,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await?;
                let replay = rss_mdm_pki_service::observations::record_in(
                    c,
                    &service.tenant.to_string(),
                    input,
                )
                .await
                .map_err(|e| match e {
                    rss_mdm_pki_service::Error::Conflict => Error::Conflict,
                    _ => Error::Storage,
                })?;
                Ok(Change {
                    value: (),
                    replay,
                    digest: d.clone(),
                })
            })
        })
        .await
        .map_err(Into::into)
    }
}
