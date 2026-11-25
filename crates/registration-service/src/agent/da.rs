//! DA authority front end to the shared certificate registration state machine.
//! ref: sqlx-core/src/transaction.rs@v0.9.0.
use super::*;
use crate::device::{ConsumerUse, DevicePrincipal, RegistrationKind};
use rss_mdm_agent_wire::{da, pki::Purpose};
use rss_mdm_authorization_service::Permission;
use rss_mdm_certificate::ClientCertificateEvidence;

pub struct Assembly {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub probe: rss_transactional_messaging::fence::ExecutionBinding,
    pub store: Arc<Store>,
    pub audit: Arc<AuditStore>,
    pub issuer: Arc<DeviceIssuer>,
    pub clock: Arc<dyn Clock>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
}
pub struct RegistrationService {
    inner: Service,
}

impl RegistrationService {
    pub fn execution(
        &self,
        tenant: rss_request_context::TenantId,
    ) -> rss_transactional_messaging::fence::ExecutionBinding {
        self.inner.execution(tenant)
    }
    pub fn new(a: Assembly) -> Result<Self, Error> {
        if a.store.profile() != rss_mdm_install_support::StorageProfile::Da
            || a.issuer.profile() != a.store.profile()
            || a.issuer.purpose() != Purpose::DaDevice
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            inner: Service {
                cursor: a.cursor,
                storage: a.probe.storage(),
                expected_epoch: a.probe.epoch(),
                store: a.store,
                audit: a.audit,
                origins: None,
                issuer: a.issuer,
                clock: a.clock,
                protection: a.protection,
                binding: None,
                native: None,
                installations: None,
                bootstrap: None,
            },
        })
    }
    pub fn profile(&self) -> rss_mdm_install_support::StorageProfile {
        self.inner.profile()
    }
    pub fn service_id(&self) -> Result<Uuid, Error> {
        self.inner.service_id()
    }
    pub async fn trust(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Arc<DeviceIdentityTrust>, Error> {
        self.inner.trust(execution).await
    }
    pub async fn authenticate(
        &self,
        peer: &ClientCertificateEvidence,
    ) -> Result<DevicePrincipal, Failure> {
        self.inner.authenticate(peer).await
    }
    pub async fn device_trust(
        &self,
        tenant: rss_request_context::TenantId,
        peer: Option<&ClientCertificateEvidence>,
    ) -> Result<rss_mdm_agent_wire::pki::Trust, Failure> {
        self.inner.device_trust(tenant, peer).await
    }
    pub async fn acknowledge_trust(
        &self,
        peer: &ClientCertificateEvidence,
        input: &rss_mdm_agent_wire::pki::Acknowledgement,
        a: &RequestAudit,
    ) -> Result<(), Failure> {
        self.inner.acknowledge_trust(peer, input, a).await
    }
    pub async fn grant(
        &self,
        p: &AuthorizedPrincipal,
        input: &da::GrantRequest,
        a: &RequestAudit,
    ) -> Result<da::Grant, Failure> {
        self.create(Authority::Administrator(p, None), input, a)
            .await
    }
    pub async fn recover(
        &self,
        p: &AuthorizedPrincipal,
        registration: rss_mdm_agent_wire::DeviceId,
        input: &da::GrantRequest,
        a: &RequestAudit,
    ) -> Result<da::Grant, Failure> {
        self.create(Authority::Administrator(p, Some(registration)), input, a)
            .await
    }
    pub async fn renew(
        &self,
        peer: &ClientCertificateEvidence,
        input: &da::GrantRequest,
        a: &RequestAudit,
    ) -> Result<da::Grant, Failure> {
        let p = self.authenticate(peer).await?;
        a.bind_scope(p.binding()).map_err(|_| Error::Unauthorized)?;
        self.create(Authority::Device(&p), input, a).await
    }
    async fn create(
        &self,
        authority: Authority<'_>,
        input: &da::GrantRequest,
        a: &RequestAudit,
    ) -> Result<da::Grant, Failure> {
        let s = &self.inner;
        version(wire::API_VERSION, input.operation_id)?;
        if !(60..=604800).contains(&input.expires_in_seconds) || input.csr.len() > 43692 {
            return Err(Error::Malformed.into());
        }
        if let Authority::Administrator(p, _) = &authority {
            s.proof(p, a)?;
        }
        let der = STANDARD.decode(&input.csr).map_err(|_| Error::Malformed)?;
        let csr =
            VerifiedDeviceCsr::verify(&der, Purpose::DaDevice).map_err(|_| Error::Malformed)?;
        let bound = hex(csr.spki());
        let d = digest(&("da_device", authority.target(), input))?;
        a.operation(
            input.operation_id,
            "da_registration_grant",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        s.write(a, (s, authority, input, a, bound, d), |ctx, c| {
            Box::pin(async move {
                let (s, authority, input, a, bound, d) = ctx;
                let profile = s.profile();
                let tenant = a.binding()?.tenant().to_string();
                if crate::device::installation_in(profile, c).await? != s.service_id()? {
                    return Err(Error::Forbidden);
                }
                let (actor, instance, source) = match authority {
                    Authority::Administrator(p, target) => (
                        p.principal_id().to_owned(),
                        p.instance_id().to_owned(),
                        if target.is_some() {
                            "recovery"
                        } else {
                            "administrator"
                        },
                    ),
                    Authority::Device(p) => (
                        p.device().to_string(),
                        p.installation().to_string(),
                        "renewal",
                    ),
                };
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2630))")
                    .bind(format!("{tenant}:da:{source}:{}", input.operation_id))
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                let old = sqlx::query(crate::storage_profile::sql(profile).da_grant_operation)
                    .bind(&tenant)
                    .bind(source)
                    .bind(input.operation_id)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?;
                let (device, predecessor) = if let Some(registration) = authority.target() {
                    let row =
                        sqlx::query(crate::storage_profile::sql(profile).da_current_registration)
                            .bind(&tenant)
                            .bind(registration.into_uuid())
                            .fetch_optional(&mut *c)
                            .await
                            .map_err(db)?
                            .ok_or(Error::Forbidden)?;
                    (
                        row.try_get::<uuid::Uuid, _>("device")
                            .and_then(crate::database::device_id)
                            .map_err(db)?,
                        Some(row.try_get::<Uuid, _>("credential").map_err(db)?),
                    )
                } else {
                    (
                        old.as_ref()
                            .map(|r| {
                                r.try_get::<uuid::Uuid, _>("device")
                                    .and_then(crate::database::device_id)
                                    .map_err(db)
                            })
                            .transpose()?
                            .unwrap_or_else(rss_mdm_agent_wire::DeviceId::new_v4),
                        None,
                    )
                };
                match authority {
                    Authority::Administrator(p, target) => {
                        rss_mdm_authorization_service::lock_on(
                            p.authority_profile(),
                            c,
                            &tenant,
                            p.instance_id(),
                        )
                        .await?;
                        rss_mdm_authorization_service::snapshot_on(
                            p.authority_profile(),
                            c,
                            &tenant,
                            p.instance_id(),
                        )
                        .await?
                        .require(
                            p,
                            if target.is_some() {
                                Permission::Credentials
                            } else {
                                Permission::Enrollment
                            },
                            Some(&device),
                        )
                        .map_err(|_| Error::Forbidden)?;
                    }
                    Authority::Device(p) => {
                        crate::device::require_use_in(c, p, ConsumerUse::DaConfiguration).await?;
                    }
                }
                crate::device::store::lock_registration(
                    profile,
                    c,
                    &tenant,
                    &device,
                    RegistrationKind::DaDevice,
                )
                .await?;
                let predecessor = if let Some(registration) = authority.target() {
                    crate::lifecycle::require_work_in(profile, c, &tenant, &device).await?;
                    // Re-read after the registration fence: a competing renewal may have
                    // replaced the credential while authorization was being checked.
                    let row =
                        sqlx::query(crate::storage_profile::sql(profile).da_current_registration)
                            .bind(&tenant)
                            .bind(registration.into_uuid())
                            .fetch_optional(&mut *c)
                            .await
                            .map_err(db)?
                            .ok_or(Error::Forbidden)?;
                    if row
                        .try_get::<uuid::Uuid, _>("device")
                        .and_then(crate::database::device_id)
                        .map_err(db)?
                        != device
                    {
                        return Err(Error::Forbidden);
                    }
                    Some(row.try_get::<Uuid, _>("credential").map_err(db)?)
                } else {
                    predecessor
                };
                a.target_device(&device);
                if let Some(old) = old {
                    if old.try_get::<String, _>("request_digest").map_err(db)? != *d
                        || old.try_get::<String, _>("actor").map_err(db)? != actor
                        || old.try_get::<String, _>("instance").map_err(db)? != instance
                    {
                        return Err(Error::Conflict);
                    }
                    check_secret(&tenant, &old, &input.secret)?;
                    return Ok(Change {
                        value: receipt(&old)?,
                        replay: true,
                    });
                }
                let id = Uuid::new_v4();
                sqlx::query(crate::storage_profile::sql(profile).da_insert_grant)
                    .bind(&tenant)
                    .bind(id)
                    .bind(input.operation_id)
                    .bind(source)
                    .bind(actor)
                    .bind(instance)
                    .bind(device.into_uuid())
                    .bind(secret_digest(&tenant, id, &input.secret))
                    .bind(&*d)
                    .bind(&*bound)
                    .bind(f64::from(input.expires_in_seconds))
                    .bind(predecessor)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                Ok(Change {
                    value: receipt(&grant_row(profile, c, &tenant, id).await?)?,
                    replay: false,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
    pub async fn issue(
        &self,
        input: &da::CertificateRequest,
        a: &RequestAudit,
    ) -> Result<wire::Candidate, Failure> {
        self.inner
            .issue_request(
                &issuance::CertificateInput {
                    wire_version: wire::API_VERSION,
                    operation_id: input.operation_id,
                    grant_id: input.grant_id,
                    secret: input.secret.clone(),
                    csr: input.csr.clone(),
                    runtime: None,
                },
                a,
            )
            .await
    }
    pub async fn recover_issuance(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: &wire::RecoverIssuance,
        a: &RequestAudit,
    ) -> Result<wire::Candidate, Failure> {
        self.inner.recover_issuance(p, id, input, a).await
    }
    pub async fn activate(
        &self,
        peer: &ClientCertificateEvidence,
        input: &wire::ActivationRequest,
        a: &RequestAudit,
    ) -> Result<da::Registration, Failure> {
        self.inner
            .activate_certificate(peer, input, a)
            .await?
            .da()
            .map_err(Into::into)
    }
    pub async fn status(&self, input: &wire::StatusRequest) -> Result<da::Progress, Failure> {
        version(input.wire_version, input.operation_id)?;
        let s = &self.inner;
        let tenant = s
            .store
            .locate_grant(input.grant_id)
            .await?
            .ok_or(Error::Unauthorized)?
            .0
            .to_string();
        let mut tx = s.store.begin(&tenant).await?;
        let row = grant_row(s.profile(), &mut tx, &tenant, input.grant_id).await?;
        if row
            .try_get::<String, _>("certificate_purpose")
            .map_err(db)?
            != "da_device"
            || row.try_get::<Uuid, _>("operation_id").map_err(db)? != input.operation_id
        {
            return Err(Error::Unauthorized.into());
        }
        check_secret(&tenant, &row, &input.secret)?;
        let issuance =
            sqlx::query(crate::storage_profile::sql(s.profile()).certificate_grants_progress_1)
                .bind(&tenant)
                .bind(input.grant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        let (issuance_id, issuance_unknown, registration) = if let Some(i) = issuance {
            let result = i
                .try_get::<Option<serde_json::Value>, _>("activation_result")
                .map_err(db)?
                .map(|v| {
                    serde_json::from_value::<ActivationResult>(v)
                        .map_err(|_| Error::Corrupt)?
                        .da()
                })
                .transpose()?;
            (
                Some(i.try_get("id").map_err(db)?),
                i.try_get::<String, _>("state").map_err(db)? != "issued",
                result,
            )
        } else {
            (None, false, None)
        };
        let result = da::Progress {
            grant: receipt(&row)?,
            issuance_id,
            issuance_unknown,
            registration,
        };
        tx.commit().await.map_err(db)?;
        Ok(result)
    }
    pub async fn revoke(
        &self,
        p: &AuthorizedPrincipal,
        registration: rss_mdm_agent_wire::DeviceId,
        operation: Uuid,
        a: &RequestAudit,
    ) -> Result<da::RevocationReceipt, Failure> {
        let s = &self.inner;
        s.proof(p, a)?;
        version(wire::API_VERSION, operation)?;
        a.operation(
            operation,
            "da_registration_revoke",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        s.write(a, (s, p, registration, operation, a), |ctx, c| {
            Box::pin(async move {
                let (s, p, registration, operation, a) = ctx;
                let profile = s.profile();
                let tenant = a.binding()?.tenant().to_string();
                let row = sqlx::query(crate::storage_profile::sql(profile).da_registration)
                    .bind(&tenant)
                    .bind(registration.into_uuid())
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?
                    .ok_or(Error::Forbidden)?;
                let device: rss_mdm_agent_wire::DeviceId = row
                    .try_get::<uuid::Uuid, _>("device")
                    .and_then(crate::database::device_id)
                    .map_err(db)?;
                rss_mdm_authorization_service::lock_on(
                    p.authority_profile(),
                    c,
                    &tenant,
                    p.instance_id(),
                )
                .await?;
                rss_mdm_authorization_service::snapshot_on(
                    p.authority_profile(),
                    c,
                    &tenant,
                    p.instance_id(),
                )
                .await?
                .require(p, Permission::Credentials, Some(&device))
                .map_err(|_| Error::Forbidden)?;
                let d = digest(&("da_revoke", &*registration))?;
                let op = crate::operations::Operation {
                    actor: crate::operations::Actor::from_authorized(p),
                    key: *operation,
                    digest: &d,
                };
                if let Some(old) = crate::operations::replay(profile, c, &op).await? {
                    return Ok(Change {
                        value: serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,
                        replay: true,
                    });
                }
                crate::device::store::lock_registration(
                    profile,
                    c,
                    &tenant,
                    &device,
                    RegistrationKind::DaDevice,
                )
                .await?;
                // Freeze the actual credential before retirement changes its state.
                let current =
                    sqlx::query(crate::storage_profile::sql(profile).da_current_registration)
                        .bind(&tenant)
                        .bind(device.into_uuid())
                        .fetch_optional(&mut *c)
                        .await
                        .map_err(db)?
                        .ok_or(Error::Conflict)?;
                let credential: Uuid = current.try_get("credential").map_err(db)?;
                a.target_device(&device);
                rss_mdm_pki_service::certificates::revoke_registration_in(
                    profile,
                    c,
                    &tenant,
                    &*registration,
                )
                .await
                .map_err(|_| Error::Storage)?;
                crate::device::store::retire_state_in(
                    profile,
                    c,
                    &tenant,
                    &*registration,
                    "revoked",
                    s.store.retirement.events(),
                )
                .await?;
                let value = da::RevocationReceipt {
                    service_id: s.service_id()?,
                    tenant: Uuid::parse_str(&tenant).map_err(|_| Error::Corrupt)?,
                    credential,
                    operation_id: *operation,
                    device: *registration,
                };
                crate::operations::save(
                    profile,
                    c,
                    &op,
                    &serde_json::to_string(&value).map_err(|_| Error::Corrupt)?,
                    a,
                    false,
                )
                .await?;
                Ok(Change {
                    value,
                    replay: false,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
    /// TLS proves key possession. The previously activated leaf may recover only its own
    /// committed revoke result, even after ordinary device authorization has ended.
    pub async fn revocation_receipt(
        &self,
        peer: &ClientCertificateEvidence,
        a: &RequestAudit,
    ) -> Result<da::RevocationReceipt, Failure> {
        let s = &self.inner;
        let leaf = peer.chain().first().ok_or(Error::Unauthorized)?;
        let fingerprint: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        let tenant = s
            .store
            .locate_certificate(fingerprint)
            .await?
            .ok_or(Error::Unauthorized)?;
        let binding = s.execution(tenant);
        let tenant = tenant.to_string();
        let mut tx = s.store.begin(&tenant).await?;
        super::fence_on(&mut tx, binding).await?;
        let result: Option<String> = sqlx::query_scalar(
            "SELECT o.result FROM rss_da.certificate_issuances i
             JOIN rss_da.credentials k ON (k.tenant_id,k.id)=(i.tenant_id,i.credential)
             JOIN rss_da.registration_operations o ON (o.tenant_id,o.device)=(k.tenant_id,k.device)
             WHERE i.tenant_id=$1::uuid AND i.fingerprint=$2
               AND k.purpose='da_device' AND k.channel IS NULL AND k.state='revoked'
               AND o.action='da_registration_revoke' AND o.result::jsonb->>'credential'=k.id::text",
        )
        .bind(&tenant)
        .bind(hex(fingerprint))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let receipt: da::RevocationReceipt =
            serde_json::from_str(&result.ok_or(Error::Unauthorized)?)
                .map_err(|_| Error::Corrupt)?;
        if receipt.service_id != s.service_id()? || receipt.tenant.to_string() != tenant {
            return Err(Error::Unauthorized.into());
        }
        tx.commit().await.map_err(db)?;
        a.bind_scope(binding).map_err(|_| Error::Unauthorized)?;
        a.target_device(&receipt.device);
        Ok(receipt)
    }
}
enum Authority<'a> {
    Administrator(
        &'a AuthorizedPrincipal,
        Option<rss_mdm_agent_wire::DeviceId>,
    ),
    Device(&'a DevicePrincipal),
}
impl Authority<'_> {
    fn target(&self) -> Option<&rss_mdm_agent_wire::DeviceId> {
        match self {
            Self::Administrator(_, v) => v.as_ref(),
            Self::Device(p) => Some(p.device()),
        }
    }
}
fn receipt(row: &PgRow) -> Result<da::Grant, Error> {
    Ok(da::Grant {
        grant_id: row.try_get("id").map_err(db)?,
        operation_id: row.try_get("operation_id").map_err(db)?,
        device: row
            .try_get::<uuid::Uuid, _>("device")
            .and_then(crate::database::device_id)
            .map_err(db)?,
        expires_at: row.try_get("expiry").map_err(db)?,
    })
}
