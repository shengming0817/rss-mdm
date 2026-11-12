use super::*;
use crate::device::{self, DevicePrincipal};
use rss_mdm_certificate::ClientCertificateEvidence;
impl Service {
    pub async fn activate(
        &self,
        peer: &ClientCertificateEvidence,
        input: &wire::ActivationRequest,
        a: &RequestAudit,
    ) -> Result<wire::ActivationReceipt, Failure> {
        if self.issuer.purpose() != rss_mdm_agent_wire::pki::Purpose::Agent {
            return Err(Error::Forbidden.into());
        }
        self.activate_certificate(peer, input, a)
            .await?
            .agent()
            .map_err(Into::into)
    }
    pub(super) async fn activate_certificate(
        &self,
        peer: &ClientCertificateEvidence,
        input: &wire::ActivationRequest,
        a: &RequestAudit,
    ) -> Result<ActivationResult, Failure> {
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
            "device_certificate_activate",
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
                    let device: rss_mdm_agent_wire::DeviceId = g
                        .try_get::<uuid::Uuid, _>("device")
                        .and_then(crate::database::device_id)
                        .map_err(db)?;
                    a.target_device(&device);
                    device::store::lock_registration(
                        profile,
                        c,
                        &tenant,
                        &device,
                        service.registration_kind(),
                    )
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
                        let out: ActivationResult =
                            serde_json::from_value(result).map_err(|_| Error::Corrupt)?;
                        let p = device::authenticate_endpoint_in(profile, c, service.tenant, proof)
                            .await?;
                        a.target_device(p.device());
                        return Ok(Change {
                            value: out,
                            replay: true,
                        });
                    }
                    crate::lifecycle::require_work_in(profile, c, &tenant, &device).await?;
                    service.grant_live(c, &g).await?;
                    if service.issuer.purpose() == rss_mdm_agent_wire::pki::Purpose::Agent
                        && g.try_get::<Option<Uuid>, _>("predecessor")
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
                    let runtime_profile: Option<wire::RuntimeProfile> =
                        serde_json::from_value(row.try_get("profile").map_err(db)?)
                            .map_err(|_| Error::Corrupt)?;
                    let credential = Uuid::new_v4();
                    let runtime = if let Some(predecessor) =
                        g.try_get::<Option<Uuid>, _>("predecessor").map_err(db)?
                    {
                        let old = sqlx::query(
                            crate::storage_profile::sql(profile).agent_activation_activate_5,
                        )
                        .bind(&tenant)
                        .bind(device.into_uuid())
                        .bind(predecessor)
                        .bind(service.registration_channel())
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
                        let old_receipt: ActivationResult =
                            serde_json::from_value(result).map_err(|_| Error::Corrupt)?;
                        let previous_profile: serde_json::Value = sqlx::query_scalar(
                            crate::storage_profile::sql(profile).agent_activation_activate_7,
                        )
                        .bind(&tenant)
                        .bind(predecessor)
                        .fetch_one(&mut *c)
                        .await
                        .map_err(db)?;
                        let previous: Option<wire::RuntimeProfile> =
                            serde_json::from_value(previous_profile).map_err(|_| Error::Corrupt)?;
                        let runtime = match (&runtime_profile, &previous, old_receipt) {
                            (Some(current), Some(previous), ActivationResult::Agent(old))
                                if current.platform == previous.platform
                                    && current.architecture == previous.architecture
                                    && old.runtime.capabilities == current.capabilities =>
                            {
                                Some(old.runtime)
                            }
                            (None, None, ActivationResult::Da(_)) => None,
                            _ => return Err(Error::Conflict),
                        };
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
                        runtime
                    } else {
                        let epoch = Uuid::new_v4();
                        sqlx::query(
                            crate::storage_profile::sql(profile).agent_activation_activate_10,
                        )
                        .bind(&tenant)
                        .bind(device.into_uuid())
                        .bind(grant)
                        .bind(epoch)
                        .bind(service.registration_channel())
                        .bind(service.registration_purpose().as_str())
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                        crate::webhook::device(
                            service.store.retirement.events(),
                            c,
                            &tenant,
                            &device,
                            rss_mdm_pki_service::registry::purpose(service.issuer.purpose()),
                            "active",
                        )
                        .await?;
                        for source in
                            if service.registration_kind() == device::RegistrationKind::Agent {
                                &[
                                    "agent.builtin",
                                    "agent.script",
                                    "agent.osquery",
                                    "agent.native",
                                ][..]
                            } else {
                                &[]
                            }
                        {
                            sqlx::query(
                                crate::storage_profile::sql(profile).agent_activation_activate_11,
                            )
                            .bind(&tenant)
                            .bind(device.into_uuid())
                            .bind(source)
                            .bind(epoch)
                            .execute(&mut *c)
                            .await
                            .map_err(db)?;
                        }

                        if let (Some(binding), Some(runtime_profile)) =
                            (&service.binding, &runtime_profile)
                        {
                            Some(
                                binding
                                    .bind(
                                        c,
                                        Binding {
                                            profile,
                                            tenant: service.tenant,
                                            device,
                                            epoch,
                                            operation: input.operation_id,
                                        },
                                        runtime_profile,
                                    )
                                    .await?,
                            )
                        } else if service.registration_kind() == device::RegistrationKind::DaDevice
                            && runtime_profile.is_none()
                        {
                            None
                        } else {
                            return Err(Error::Forbidden);
                        }
                    };
                    sqlx::query(crate::storage_profile::sql(profile).agent_activation_activate_12)
                        .bind(&tenant)
                        .bind(credential)
                        .bind(device.into_uuid())
                        .bind(&*fingerprint)
                        .bind(service.registration_channel())
                        .bind(service.registration_purpose().as_str())
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
                        rss_mdm_pki_service::registry::purpose(service.issuer.purpose()),
                        &device,
                        &issuer,
                        &leaf,
                    )
                    .await
                    .map_err(|_| Error::Storage)?;
                    let out = match runtime {
                        Some(runtime) => ActivationResult::Agent(wire::ActivationReceipt {
                            wire_version: wire::API_VERSION,
                            issuance_id: input.issuance_id,
                            operation_id: input.operation_id,
                            runtime,
                        }),
                        None => ActivationResult::Da(rss_mdm_agent_wire::da::Registration {
                            service_id: service.service_id()?,
                            tenant: Uuid::parse_str(&tenant).map_err(|_| Error::Corrupt)?,
                            device,
                            credential,
                            issuance_id: input.issuance_id,
                            operation_id: input.operation_id,
                        }),
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
        let p = device::authenticate_endpoint_in(profile, &mut tx, self.tenant, &proof).await?;
        tx.commit().await.map_err(db)?;
        Ok(p)
    }
}
