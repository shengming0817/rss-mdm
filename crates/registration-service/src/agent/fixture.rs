//! Minimal current credential prerequisites for downstream integration consumers.
use super::*;
use rss_mdm_agent_wire::enroll::configuration as wc;
use rss_mdm_certificate::agent::IssuedAgentCertificate;

/// One independently signed current peer for a configuration's prepared prefix.
/// The request carries the real configuration, target installation and distinct CSR.
pub struct ConfigurationPeerSeed {
    pub device: String,
    pub request: wc::Exchange,
    pub chain: Vec<Vec<u8>>,
    pub validity: std::ops::Range<i64>,
}
struct PeerSeed {
    device: String,
    profile: wire::RuntimeProfile,
    csr_bytes: Vec<u8>,
    chain: Vec<Vec<u8>>,
    validity: std::ops::Range<i64>,
}
impl Service {
    /// Prepare a task peer with a real CA certificate and current runtime binding.
    pub async fn seed_peer(
        &self,
        device: &str,
        profile: wire::RuntimeProfile,
        csr_bytes: Vec<u8>,
        chain: Vec<Vec<u8>>,
        validity: std::ops::Range<i64>,
    ) -> Result<(IssuedAgentCertificate, runtime::BindingProfile), Error> {
        let mut tx = self.store.begin(&self.tenant.to_string()).await?;
        let result = self
            .seed_peer_in(
                &mut tx,
                PeerSeed {
                    device: device.into(),
                    profile,
                    csr_bytes,
                    chain,
                    validity,
                },
                None,
            )
            .await?;
        tx.commit().await.map_err(db)?;
        Ok(result)
    }

    /// Prepare only an unconsumed configuration's prefix; live boundary allocations
    /// and their issuance remain production operations in the consuming test.
    pub async fn seed_configuration_peers(
        &self,
        configuration_id: Uuid,
        seeds: Vec<ConfigurationPeerSeed>,
    ) -> Result<Vec<String>, Error> {
        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let owner = sqlx::query("SELECT * FROM mdm_access.agent_configurations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
            .bind(&tenant).bind(configuration_id).fetch_one(&mut *tx).await.map_err(db)?;
        let stored: wc::Configuration =
            serde_json::from_value(owner.try_get("document").map_err(db)?)
                .map_err(|_| Error::Corrupt)?;
        let occupied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND configuration_id=$2)")
            .bind(&tenant).bind(configuration_id).fetch_one(&mut *tx).await.map_err(db)?;
        if seeds.is_empty()
            || occupied
            || owner.try_get::<String, _>("state").map_err(db)? != "available"
            || stored.tenant_id.to_string() != tenant
            || stored.expires_at <= now(&mut tx).await?
            || matches!(stored.quantity, wc::Quantity::Finite { count } if seeds.len() >= count.get() as usize)
        {
            return Err(Error::Malformed);
        }
        let mut devices = Vec::with_capacity(seeds.len());
        for seed in seeds {
            self.configuration_signer.verify(&seed.request.file)?;
            if seed.request.file.configuration != stored {
                return Err(Error::Malformed);
            }
            let package = self
                .installations
                .verify(&mut tx, &tenant, &seed.request.installation)
                .await?;
            let target = wc::Target {
                platform: seed.request.runtime.platform,
                architecture: seed.request.runtime.architecture,
            };
            if package.tenant_id != stored.tenant_id
                || package.target != target
                || !stored.targets.contains(&target)
                || !stored.channels.contains(&package.channel)
            {
                return Err(Error::Malformed);
            }
            let binding = serde_json::json!({"runtime":seed.request.runtime,"installation":seed.request.installation});
            let csr_bytes = STANDARD
                .decode(&seed.request.csr)
                .map_err(|_| Error::Malformed)?;
            let device = seed.device;
            self.seed_peer_in(
                &mut tx,
                PeerSeed {
                    device: device.clone(),
                    profile: seed.request.runtime,
                    csr_bytes,
                    chain: seed.chain,
                    validity: seed.validity,
                },
                Some((configuration_id, &owner, binding)),
            )
            .await?;
            devices.push(device);
        }
        tx.commit().await.map_err(db)?;
        Ok(devices)
    }

    async fn seed_peer_in(
        &self,
        c: &mut PgConnection,
        seed: PeerSeed,
        configuration: Option<(Uuid, &PgRow, serde_json::Value)>,
    ) -> Result<(IssuedAgentCertificate, runtime::BindingProfile), Error> {
        let PeerSeed {
            device,
            profile,
            csr_bytes,
            chain,
            validity,
        } = seed;
        let device = device.as_str();
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
        sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2)")
            .bind(&tenant)
            .bind(device)
            .execute(&mut *c)
            .await
            .map_err(db)?;
        let (source, actor, instance, configuration_id, configuration_binding) = match configuration
        {
            Some((id, owner, binding)) => (
                "configuration",
                owner.try_get::<String, _>("creator").map_err(db)?,
                owner.try_get::<String, _>("instance").map_err(db)?,
                Some(id),
                Some(binding),
            ),
            None => (
                "download",
                "integration-fixture".into(),
                "integration-fixture".into(),
                None,
                None,
            ),
        };
        sqlx::query("INSERT INTO mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,spki,state,expires_at,configuration_id,configuration_binding) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,'consumed',clock_timestamp()+interval '1 hour',$11,$12)")
            .bind(&tenant).bind(grant).bind(operation).bind(source).bind(actor).bind(instance)
            .bind(device).bind(profile_value["platform"].as_str().ok_or(Error::Malformed)?)
            .bind(&request_digest).bind(hex(csr.spki())).bind(configuration_id).bind(configuration_binding)
            .execute(&mut *c).await.map_err(db)?;
        sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,agent_grant_id,state,purpose,epoch) VALUES($1::uuid,$2,$3,'agent',1,$4,'active','primary',$5)")
            .bind(&tenant).bind(registration).bind(device).bind(grant).bind(epoch).execute(&mut *c).await.map_err(db)?;
        for source in [
            "agent.builtin",
            "agent.script",
            "agent.osquery",
            "agent.native",
        ] {
            sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled) VALUES($1::uuid,$2,$3,$4,true)")
                .bind(&tenant).bind(registration).bind(source).bind(epoch).execute(&mut *c).await.map_err(db)?;
        }
        let runtime = self
            .binding
            .bind(
                c,
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
            .bind(&tenant).bind(credential).bind(registration).bind(&fingerprint).execute(&mut *c).await.map_err(db)?;
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
            .execute(&mut *c).await.map_err(db)?;
        rss_mdm_pki_service::certificates::record_in(
            c,
            &tenant,
            "agent",
            registration,
            &issuer_hex,
            &issued.chain[0],
        )
        .await
        .map_err(|_| Error::Storage)?;
        Ok((issued, runtime))
    }
}
