//! Minimal current credential prerequisites for downstream integration consumers.
use super::*;
use rss_mdm_certificate::agent::IssuedAgentCertificate;

impl Service {
    /// Prepare a new task peer with an actual CA certificate and current runtime binding.
    /// Enrollment authorization, activation HTTP, and their audit receipts are not exercised.
    pub async fn seed_peer(
        &self,
        device: &str,
        profile: wire::RuntimeProfile,
        csr_bytes: Vec<u8>,
        chain: Vec<Vec<u8>>,
        validity: std::ops::Range<i64>,
    ) -> Result<
        (
            IssuedAgentCertificate,
            rss_mdm_agent_wire::runtime::BindingProfile,
        ),
        Error,
    > {
        profile.validate().map_err(|_| Error::Malformed)?;
        let tenant = self.tenant.to_string();
        let tenant_uuid = Uuid::parse_str(&tenant).map_err(|_| Error::Malformed)?;
        let csr = rss_mdm_certificate::agent::VerifiedAgentCsr::verify(&csr_bytes)
            .map_err(|_| Error::Malformed)?;
        let identity = rss_mdm_certificate::agent::identity(tenant_uuid, device)
            .map_err(|_| Error::Malformed)?;
        let now = self.now()?;
        let start = validity.start;
        let end = validity.end;
        let grant = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let issuer = self.trust().issuer_digest();
        let issuer_hex = hex(issuer);
        let authority = self.issuer.authority_digest(issuer)?;
        let issued = self
            .trust()
            .validate_issued_for(issuer, chain, &csr, &identity, validity, now)
            .map_err(|_| Error::Malformed)?;
        let fingerprint = hex(issued.metadata.fingerprint);
        let registration = Uuid::new_v4();
        let credential = Uuid::new_v4();
        let epoch = Uuid::new_v4();
        let profile_value = serde_json::to_value(&profile).map_err(|_| Error::Malformed)?;
        let request_digest = digest(&profile_value)?;
        let mut tx = self.store.begin(&tenant).await?;
        sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2)")
            .bind(&tenant)
            .bind(device)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("INSERT INTO mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,spki,state,expires_at) VALUES($1::uuid,$2,$3,'download','integration-fixture','integration-fixture',$4,$5,$6,$6,$7,'consumed',clock_timestamp()+interval '1 hour')")
            .bind(&tenant).bind(grant).bind(operation).bind(device).bind(profile_value["platform"].as_str().ok_or(Error::Malformed)?)
            .bind(&request_digest).bind(hex(csr.spki())).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,agent_grant_id,state,purpose,epoch) VALUES($1::uuid,$2,$3,'agent',1,$4,'active','primary',$5)")
            .bind(&tenant).bind(registration).bind(device).bind(grant).bind(epoch).execute(&mut *tx).await.map_err(db)?;
        for source in [
            "agent.builtin",
            "agent.script",
            "agent.osquery",
            "agent.native",
        ] {
            sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES($1::uuid,$2,$3,$4,true)")
                .bind(&tenant).bind(registration).bind(source).bind(epoch).execute(&mut *tx).await.map_err(db)?;
        }
        let runtime = self
            .binding
            .bind(
                &mut tx,
                Binding {
                    tenant: self.tenant,
                    device: device.into(),
                    registration,
                    generation: 1,
                    epoch,
                    operation,
                },
                &profile,
            )
            .await?;
        sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2,$3,'agent',$4,'active')")
            .bind(&tenant).bind(credential).bind(registration).bind(&fingerprint).execute(&mut *tx).await.map_err(db)?;
        // The current authentication owner joins its issuance metadata to the credential.
        // Preserve a typed activation snapshot for credential retirement consumers.
        let receipt = wire::ActivationReceipt {
            wire_version: wire::API_VERSION,
            issuance_id: attempt,
            operation_id: operation,
            runtime: runtime.clone(),
        };
        let chain: Vec<String> = issued
            .chain
            .iter()
            .map(|bytes| STANDARD.encode(bytes))
            .collect();
        sqlx::query("INSERT INTO mdm_access.agent_issuances(tenant_id,id,grant_id,operation_id,request_digest,authority_digest,csr,spki,identity,profile,not_before,not_after,state,certificate_chain,metadata,fingerprint,activation_operation,activation_digest,activation_result,credential,signing_issuer) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'issued',$13,$14,$15,$4,$5,$16,$17,$18)")
            .bind(&tenant).bind(attempt).bind(grant).bind(operation).bind(&request_digest).bind(authority).bind(csr_bytes)
            .bind(hex(csr.spki())).bind(identity).bind(profile_value).bind(start).bind(end)
            .bind(serde_json::to_value(chain).map_err(|_| Error::Corrupt)?).bind(serde_json::to_value(&issued.metadata).map_err(|_| Error::Corrupt)?)
            .bind(fingerprint).bind(serde_json::to_value(receipt).map_err(|_| Error::Corrupt)?).bind(credential).bind(&issuer_hex)
            .execute(&mut *tx).await.map_err(db)?;
        rss_mdm_pki_service::certificates::record_in(
            &mut tx,
            &tenant,
            "agent",
            registration,
            &issuer_hex,
            &issued.chain[0],
        )
        .await
        .map_err(|_| Error::Storage)?;
        tx.commit().await.map_err(db)?;
        Ok((issued, runtime))
    }
}
