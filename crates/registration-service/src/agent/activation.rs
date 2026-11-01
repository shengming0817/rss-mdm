use super::*;
use crate::device::{self, DevicePrincipal};
use rss_mdm_certificate::ClientCertificateEvidence;
use rss_mdm_inventory::Channel;
impl Service {
    pub async fn activate(
        &self,
        peer: &ClientCertificateEvidence,
        input: &wire::ActivationRequest,
        a: &RequestAudit,
    ) -> Result<wire::ActivationReceipt, Failure> {
        let profile = self.profile();

        version(input.wire_version, input.operation_id)?;
        let proof = self
            .trust()
            .verify_peer(peer, self.now()?)
            .map_err(|_| Error::Unauthorized)?;
        let fingerprint = hex(proof.metadata().fingerprint);
        let request_digest = digest(input)?;
        a.operation(
            input.operation_id,
            "agent_certificate_activate",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(
            a,
            (self, input, a, proof, fingerprint, request_digest),
            |ctx, c| {
                Box::pin(async move {
                    let (service, input, a, proof, fingerprint, digest) = ctx;
                    let tenant = service.tenant.to_string();
                    let grant: Uuid = sqlx::query_scalar(
                        crate::storage_profile::sql(profile).agent_activation_activate_3,
                    )
                    .bind(&tenant)
                    .bind(input.issuance_id)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?
                    .ok_or(Error::Unauthorized)?;
                    let g = grant_row(profile, c, &tenant, grant).await?;
                    let row = sqlx::query(
                        crate::storage_profile::sql(profile).agent_activation_activate_4,
                    )
                    .bind(&tenant)
                    .bind(input.issuance_id)
                    .fetch_one(&mut *c)
                    .await
                    .map_err(db)?;
                    if row
                        .try_get::<Option<String>, _>("fingerprint")
                        .map_err(db)?
                        .as_deref()
                        != Some(fingerprint)
                        || row.try_get::<String, _>("identity").map_err(db)?
                            != proof.metadata().identity
                        || row.try_get::<String, _>("spki").map_err(db)?
                            != hex(proof.metadata().spki)
                    {
                        return Err(Error::Unauthorized);
                    }
                    let device: String = g.try_get("device").map_err(db)?;
                    a.target(&device);
                    device::store::lock_channel(profile, c, &tenant, &device, Channel::Agent)
                        .await?;
                    if let Some(result) = row
                        .try_get::<Option<serde_json::Value>, _>("activation_result")
                        .map_err(db)?
                    {
                        if row.try_get::<Uuid, _>("activation_operation").map_err(db)?
                            != input.operation_id
                            || row.try_get::<String, _>("activation_digest").map_err(db)? != *digest
                        {
                            return Err(Error::Conflict);
                        }
                        let out: wire::ActivationReceipt =
                            serde_json::from_value(result).map_err(|_| Error::Corrupt)?;
                        let p = device::authenticate_agent_in(profile, c, service.tenant, proof)
                            .await?;
                        a.registration(p.registration());
                        return Ok(Change {
                            value: out,
                            replay: true,
                        });
                    }
                    crate::lifecycle::require_work_in(profile, c, &tenant, &device).await?;
                    service.grant_live(c, &g).await?;
                    if g.try_get::<Option<Uuid>, _>("target_registration")
                        .map_err(db)?
                        .is_none()
                    {
                        crate::admission::require_new_in(
                            profile,
                            c,
                            &tenant,
                            crate::quotas::Channel::Agent,
                        )
                        .await?;
                    }
                    let runtime_profile: wire::RuntimeProfile =
                        serde_json::from_value(row.try_get("profile").map_err(db)?)
                            .map_err(|_| Error::Corrupt)?;
                    let credential = Uuid::new_v4();
                    let (registration, generation, epoch, runtime) = if let Some(registration) = g
                        .try_get::<Option<Uuid>, _>("target_registration")
                        .map_err(db)?
                    {
                        let predecessor: Uuid = g.try_get("predecessor").map_err(db)?;
                        let old = sqlx::query(
                            crate::storage_profile::sql(profile).agent_activation_activate_5,
                        )
                        .bind(&tenant)
                        .bind(registration)
                        .bind(&device)
                        .bind(predecessor)
                        .fetch_optional(&mut *c)
                        .await
                        .map_err(db)?
                        .ok_or(Error::Forbidden)?;
                        if old.try_get::<String, _>("state").map_err(db)? != "active"
                            || old.try_get::<String, _>("credential_state").map_err(db)? != "active"
                        {
                            return Err(Error::Agent(wire::ErrorCode::CredentialRetired));
                        }
                        let result: serde_json::Value = sqlx::query_scalar(
                            crate::storage_profile::sql(profile).agent_activation_activate_6,
                        )
                        .bind(&tenant)
                        .bind(predecessor)
                        .fetch_one(&mut *c)
                        .await
                        .map_err(db)?;
                        let old_receipt: wire::ActivationReceipt =
                            serde_json::from_value(result).map_err(|_| Error::Corrupt)?;
                        let previous_profile: serde_json::Value = sqlx::query_scalar(
                            crate::storage_profile::sql(profile).agent_activation_activate_7,
                        )
                        .bind(&tenant)
                        .bind(predecessor)
                        .fetch_one(&mut *c)
                        .await
                        .map_err(db)?;
                        let previous: wire::RuntimeProfile =
                            serde_json::from_value(previous_profile).map_err(|_| Error::Corrupt)?;
                        if previous.platform != runtime_profile.platform
                            || previous.architecture != runtime_profile.architecture
                            || old_receipt.runtime.capabilities != runtime_profile.capabilities
                        {
                            return Err(Error::Conflict);
                        }
                        rss_mdm_pki_service::certificates::revoke_credential_in(
                            profile,
                            c,
                            &tenant,
                            predecessor,
                        )
                        .await
                        .map_err(|_| Error::Storage)?;
                        sqlx::query(
                            crate::storage_profile::sql(profile).agent_activation_activate_8,
                        )
                        .bind(&tenant)
                        .bind(predecessor)
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                        (
                            registration,
                            old.try_get::<i64, _>("generation").map_err(db)?,
                            old.try_get::<Uuid, _>("epoch").map_err(db)?,
                            old_receipt.runtime,
                        )
                    } else {
                        let registration = Uuid::new_v4();
                        let epoch = Uuid::new_v4();
                        let active: bool = sqlx::query_scalar(
                            crate::storage_profile::sql(profile).agent_activation_activate_1,
                        )
                        .bind(&tenant)
                        .bind(&device)
                        .fetch_one(&mut *c)
                        .await
                        .map_err(db)?;
                        if active {
                            return Err(Error::Conflict);
                        }
                        let generation: i64 = sqlx::query_scalar(
                            crate::storage_profile::sql(profile).agent_activation_activate_2,
                        )
                        .bind(&tenant)
                        .bind(&device)
                        .fetch_one(&mut *c)
                        .await
                        .map_err(db)?;
                        sqlx::query(
                            crate::storage_profile::sql(profile).agent_activation_activate_9,
                        )
                        .bind(&tenant)
                        .bind(&device)
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                        sqlx::query(
                            crate::storage_profile::sql(profile).agent_activation_activate_10,
                        )
                        .bind(&tenant)
                        .bind(registration)
                        .bind(&device)
                        .bind(grant)
                        .bind(epoch)
                        .bind(generation)
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                        crate::webhook::registration(
                            service.store.retirement.events(),
                            c,
                            &tenant,
                            &device,
                            registration,
                            generation,
                            "agent",
                            "active",
                        )
                        .await?;
                        for source in [
                            "agent.builtin",
                            "agent.script",
                            "agent.osquery",
                            "agent.native",
                        ] {
                            sqlx::query(
                                crate::storage_profile::sql(profile).agent_activation_activate_11,
                            )
                            .bind(&tenant)
                            .bind(registration)
                            .bind(source)
                            .bind(epoch)
                            .execute(&mut *c)
                            .await
                            .map_err(db)?;
                        }
                        let runtime = service
                            .binding
                            .bind(
                                c,
                                Binding {
                                    profile,
                                    tenant: service.tenant,
                                    device: device.clone(),
                                    registration,
                                    generation,
                                    epoch,
                                    operation: input.operation_id,
                                },
                                &runtime_profile,
                            )
                            .await?;
                        (registration, generation, epoch, runtime)
                    };
                    let _ = (generation, epoch);
                    a.registration(registration);
                    sqlx::query(crate::storage_profile::sql(profile).agent_activation_activate_12)
                        .bind(&tenant)
                        .bind(credential)
                        .bind(registration)
                        .bind(&*fingerprint)
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                    let chain: Vec<String> =
                        serde_json::from_value(row.try_get("certificate_chain").map_err(db)?)
                            .map_err(|_| Error::Corrupt)?;
                    let leaf = STANDARD
                        .decode(chain.first().ok_or(Error::Corrupt)?)
                        .map_err(|_| Error::Corrupt)?;
                    let issuer: String = row.try_get("signing_issuer").map_err(db)?;
                    rss_mdm_pki_service::certificates::record_in(
                        profile,
                        c,
                        &tenant,
                        "agent",
                        registration,
                        &issuer,
                        &leaf,
                    )
                    .await
                    .map_err(|_| Error::Storage)?;
                    let out = wire::ActivationReceipt {
                        wire_version: wire::API_VERSION,
                        issuance_id: input.issuance_id,
                        operation_id: input.operation_id,
                        runtime,
                    };
                    sqlx::query(crate::storage_profile::sql(profile).agent_activation_activate_13)
                        .bind(&tenant)
                        .bind(input.issuance_id)
                        .bind(input.operation_id)
                        .bind(&*digest)
                        .bind(serde_json::to_value(&out).map_err(|_| Error::Corrupt)?)
                        .bind(credential)
                        .execute(c)
                        .await
                        .map_err(db)?;
                    Ok(Change {
                        value: out,
                        replay: false,
                    })
                })
            },
        )
        .await
        .map_err(Into::into)
    }
    /// Recheck certificate profile, expiry and current database mapping on every request.
    pub async fn authenticate(
        &self,
        peer: &ClientCertificateEvidence,
    ) -> Result<DevicePrincipal, Failure> {
        let profile = self.profile();

        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let fingerprint = hex(Sha256::digest(&peer.chain()[0]));
        let expiry: Option<i64> = sqlx::query_scalar(
            crate::storage_profile::sql(profile).agent_activation_authenticate_1,
        )
        .bind(&tenant)
        .bind(&fingerprint)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if expiry.is_some_and(|end| end <= self.now().unwrap_or(i64::MAX)) {
            return Err(Error::Agent(wire::ErrorCode::CertificateExpired).into());
        }
        let proof = self
            .trust()
            .verify_peer(peer, self.now()?)
            .map_err(|_| Error::Unauthorized)?;
        let p = device::authenticate_agent_in(profile, &mut tx, self.tenant, &proof).await?;
        tx.commit().await.map_err(db)?;
        Ok(p)
    }
}
