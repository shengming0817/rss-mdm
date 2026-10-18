use super::*;
use crate::device::{self, DevicePrincipal};
use rss_mdm_certificate::HandshakePeer;
use rss_mdm_inventory::Channel;
impl Service {
    pub async fn activate(
        &self,
        peer: &HandshakePeer,
        input: &wire::ActivationRequest,
        a: &RequestAudit,
    ) -> Result<wire::ActivationReceipt, Failure> {
        version(input.wire_version, input.operation_id)?;
        let proof = self
            .trust()
            .verify_peer(peer, self.now()?)
            .map_err(|_| Error::Unauthorized)?;
        let fingerprint = hex(proof.metadata().fingerprint);
        let request_digest = digest(input)?;
        a.operation(input.operation_id, "agent_certificate_activate");
        self.write(
            a,
            (self, input, a, proof, fingerprint, request_digest),
            |ctx, c| {
                Box::pin(async move {
                    let (service, input, a, proof, fingerprint, digest) = ctx;
                    let tenant = service.tenant.to_string();
                    let grant: Uuid = sqlx::query_scalar(
                        r#"
SELECT grant_id FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND id=$2
"#,
                    )
                    .bind(&tenant)
                    .bind(input.issuance_id)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?
                    .ok_or(Error::Unauthorized)?;
                    let g = grant_row(c, &tenant, grant).await?;
                    let row = sqlx::query(
                        r#"
SELECT * FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE
"#,
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
                    device::store::lock_channel(c, &tenant, &device, Channel::Agent).await?;
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
                        let p = device::agent_in(c, service.tenant, proof).await?;
                        a.registration(p.registration());
                        return Ok(Change {
                            value: out,
                            replay: true,
                            digest: digest.clone(),
                        });
                    }
                    crate::lifecycle::require_work_in(c, &tenant, &device).await?;
                    service.grant_live(c, &g).await?;
                    if g.try_get::<Option<Uuid>, _>("target_registration")
                        .map_err(db)?
                        .is_none()
                    {
                        crate::admission::require_new_in(c, &tenant, crate::quotas::Channel::Agent)
                            .await?;
                    }
                    let profile: wire::RuntimeProfile =
                        serde_json::from_value(row.try_get("profile").map_err(db)?)
                            .map_err(|_| Error::Corrupt)?;
                    let credential = Uuid::new_v4();
                    let (registration, generation, epoch, runtime) = if let Some(registration) = g
                        .try_get::<Option<Uuid>, _>("target_registration")
                        .map_err(db)?
                    {
                        let predecessor: Uuid = g.try_get("predecessor").map_err(db)?;
                        let old = sqlx::query(
                            r#"
SELECT r.generation,r.epoch,k.state AS credential_state,r.state FROM mdm_access.registrations r
JOIN mdm_access.credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE
r.tenant_id=$1::uuid AND r.id=$2 AND r.device=$3 AND r.channel='agent' AND k.id=$4 FOR UPDATE OF
r,k
"#,
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
                            r#"
SELECT activation_result FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND
credential=$2
"#,
                        )
                        .bind(&tenant)
                        .bind(predecessor)
                        .fetch_one(&mut *c)
                        .await
                        .map_err(db)?;
                        let old_receipt: wire::ActivationReceipt =
                            serde_json::from_value(result).map_err(|_| Error::Corrupt)?;
                        let previous_profile: serde_json::Value = sqlx::query_scalar(
                            r#"
SELECT profile FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND credential=$2
"#,
                        )
                        .bind(&tenant)
                        .bind(predecessor)
                        .fetch_one(&mut *c)
                        .await
                        .map_err(db)?;
                        let previous: wire::RuntimeProfile =
                            serde_json::from_value(previous_profile).map_err(|_| Error::Corrupt)?;
                        if previous.platform != profile.platform
                            || previous.architecture != profile.architecture
                            || old_receipt.runtime.capabilities != profile.capabilities
                        {
                            return Err(Error::Conflict);
                        }
                        rss_mdm_pki_service::certificates::revoke_credential_in(
                            c,
                            &tenant,
                            predecessor,
                        )
                        .await
                        .map_err(|_| Error::Storage)?;
                        sqlx::query(
                            r#"
UPDATE mdm_access.credentials SET state='superseded' WHERE tenant_id=$1::uuid AND id=$2 AND
state='active'
"#,
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
                        sqlx::query(
                            r#"
INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2)
"#,
                        )
                        .bind(&tenant)
                        .bind(&device)
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                        sqlx::query(
                            r#"
INSERT INTO
mdm_access.registrations(tenant_id,id,device,channel,generation,agent_grant_id,state,purpose,epoch)
VALUES($1::uuid,$2,$3,'agent',1,$4,'active','primary',$5)
"#,
                        )
                        .bind(&tenant)
                        .bind(registration)
                        .bind(&device)
                        .bind(grant)
                        .bind(epoch)
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                        for source in [
                            "agent.builtin",
                            "agent.script",
                            "agent.osquery",
                            "agent.native",
                        ] {
                            sqlx::query(
                                r#"
INSERT INTO mdm_access.report_sources(tenant_id,registration,source,epoch,enabled)
VALUES($1::uuid,$2,$3,$4,true)
"#,
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
                                    tenant: service.tenant,
                                    device: device.clone(),
                                    registration,
                                    generation: 1,
                                    epoch,
                                    operation: input.operation_id,
                                },
                                &profile,
                            )
                            .await?;
                        (registration, 1, epoch, runtime)
                    };
                    let _ = (generation, epoch);
                    a.registration(registration);
                    sqlx::query(
                        r#"
INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state)
VALUES($1::uuid,$2,$3,'agent',$4,'active')
"#,
                    )
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
                    sqlx::query(
                        r#"
UPDATE mdm_access.agent_issuances SET
activation_operation=$3,activation_digest=$4,activation_result=$5,credential=$6 WHERE
tenant_id=$1::uuid AND id=$2
"#,
                    )
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
                        digest: digest.clone(),
                    })
                })
            },
        )
        .await
        .map_err(Into::into)
    }
    /// Recheck certificate profile, expiry and current database mapping on every request.
    pub async fn authenticate(&self, peer: &HandshakePeer) -> Result<DevicePrincipal, Failure> {
        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let fingerprint = hex(Sha256::digest(&peer.chain()[0]));
        let expiry: Option<i64> = sqlx::query_scalar(
            r#"
SELECT not_after FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND fingerprint=$2 AND
credential IS NOT NULL
"#,
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
        let p = device::agent_in(&mut tx, self.tenant, &proof).await?;
        tx.commit().await.map_err(db)?;
        Ok(p)
    }
}
