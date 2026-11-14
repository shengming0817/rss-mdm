//! Public trust selects the enrollment organization; installation ACK requires a live device credential.
use super::*;
use rss_mdm_agent_wire::pki::{Acknowledgement, Trust};
use rss_mdm_certificate::ClientCertificateEvidence;
impl Service {
    pub async fn device_trust(
        &self,
        tenant: rss_request_context::TenantId,
        peer: Option<&ClientCertificateEvidence>,
    ) -> Result<Trust, Failure> {
        // The public document is not authorization to enroll or execute work.
        let execution = if let Some(peer) = peer {
            let principal = self.authenticate(peer).await?;
            if principal.binding().tenant() != tenant {
                return Err(Error::Unauthorized.into());
            }
            principal.binding()
        } else {
            self.execution(tenant)
        };
        self.trust(execution)
            .await?
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
        let profile = self.profile();

        input.validate().map_err(|_| Error::Malformed)?;
        let p = self.authenticate(peer).await?;
        a.bind_scope(p.binding()).map_err(|_| Error::Forbidden)?;
        a.identify_device(p.device());
        a.target_device(p.device());
        a.operation(
            input.operation,
            "agent_trust_acknowledge",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let trust = self
            .trust(p.binding())
            .await?
            .trust
            .public()
            .map_err(|_| Error::Corrupt)?;
        let d = digest(&(p.device(), input))?;
        self.write(a, (self, p, input, trust, d, a), |ctx, c| {
            Box::pin(async move {
                let (service, p, input, trust, d, a) = ctx;
                crate::device::require_use_in(c, p, service.consumer_use()).await?;
                let tenant = a.binding()?.tenant().to_string();
                let actor = p.device().to_string();
                let hash = Sha256::digest(d.as_bytes()).to_vec();
                let replay = rss_mdm_pki_service::mutation::replay(
                    profile,
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
                    });
                }
                rss_mdm_pki_service::registry::Registry::acknowledge_in(
                    profile,
                    c,
                    &a.binding()?.tenant().to_string(),
                    p.device(),
                    trust,
                    input,
                )
                .await
                .map_err(|e| match e {
                    rss_mdm_pki_service::Error::Conflict => Error::Conflict,
                    _ => Error::Storage,
                })?;
                rss_mdm_pki_service::mutation::save(
                    profile,
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
        let profile = self.profile();

        input.validate().map_err(|_| Error::Malformed)?;
        let p = self.authenticate(peer).await?;
        a.bind_scope(p.binding()).map_err(|_| Error::Forbidden)?;
        if input.device_id != *p.device() {
            return Err(Error::Forbidden.into());
        }
        a.identify_device(p.device());
        a.target_device(p.device());
        a.operation(
            input.operation,
            "agent_trust_observe",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        self.write(a, (self, p, input), |ctx, c| {
            Box::pin(async move {
                let (service, p, input) = ctx;
                crate::device::require_use_in(c, p, service.consumer_use()).await?;
                let replay = rss_mdm_pki_service::observations::record_in(
                    profile,
                    c,
                    &a.binding()?.tenant().to_string(),
                    input,
                )
                .await
                .map_err(|e| match e {
                    rss_mdm_pki_service::Error::Conflict => Error::Conflict,
                    _ => Error::Storage,
                })?;
                Ok(Change { value: (), replay })
            })
        })
        .await
        .map_err(Into::into)
    }
}
