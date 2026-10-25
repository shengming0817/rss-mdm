use super::{certificate::Csr, *};
use crate::authorization::context::AuthorizedPrincipal;
use crate::{
    database::db,
    device::{BindRegistration, VerifiedChannelCredential, store::bind_in},
    enrollment::{
        Authorization,
        store::{request, uuid},
    },
};
use rss_mdm_inventory::ReportSource;
use rss_mdm_registration_service::windows_receipts::{self, Operation};
use rss_mdm_windows_mdm::provisioning::EnrollmentType;
use rss_request_context::TenantId;
use sqlx::Row;
use tokio_rustls::rustls::pki_types::CertificateDer;
use uuid::Uuid;

/// One issuance pipeline consumes either the original password authority or native admission.
pub(crate) enum IssuanceAuthority<'a> {
    Password(&'a Authorization, &'a AuthorizedPrincipal),
    Native(&'a rss_mdm_registration_service::enrollment::native::Admission),
}
impl IssuanceAuthority<'_> {
    fn coordinates(&self) -> rss_mdm_registration_service::enrollment::native::Coordinates {
        use rss_mdm_registration_service::enrollment::native::Coordinates;
        match self {
            Self::Native(p) => p.coordinates().clone(),
            Self::Password(a, p) => Coordinates {
                tenant: p.tenant_id().into(),
                id: a.id,
                device: a.device.clone(),
                actor: a.actor.clone(),
                instance: a.instance.clone(),
                version: a.version,
                expected_generation: a.expected_generation,
                operation: a.operation,
                source: a.source,
            },
        }
    }
    async fn current(&self, c: &mut sqlx::PgConnection) -> Result<sqlx::postgres::PgRow, Error> {
        if let Self::Native(proof) = self {
            proof.lock_authority_in(c).await?;
        }
        rss_mdm_registration_service::admission::lock_in(c, &self.coordinates().tenant).await?;
        match self {
            Self::Native(p) => {
                let d = p.coordinates();
                crate::device::store::lock_channel(c, &d.tenant, &d.device, d.source.channel())
                    .await?;
                p.current_request(c).await.map_err(Into::into)
            }
            Self::Password(a, p) => {
                let r = request(c, p.tenant_id(), a.id).await?;
                current(&r, a, p)?;
                Ok(r)
            }
        }
    }
    fn check_live(&self) -> Result<(), Error> {
        match self {
            Self::Native(p) => p.check_live().map_err(Into::into),
            Self::Password(a, p) => a.authorize(p).map_err(Into::into),
        }
    }
}

pub struct Intent {
    pub protocol_device: Option<String>,
    pub enrollment_type: EnrollmentType,
    pub csr: Vec<u8>,
    pub profile: Vec<u8>,
    pub issuer: Vec<u8>,
    pub configuration: String,
    pub registration: Uuid,
    pub credential: Uuid,
    pub epoch: Uuid,
    pub sealed: Vec<u8>,
}
pub(crate) fn intent(row: sqlx::postgres::PgRow) -> Result<Intent, Error> {
    Ok(Intent {
        protocol_device: row.try_get("protocol_device").map_err(db)?,
        enrollment_type: match row
            .try_get::<String, _>("enrollment_type")
            .map_err(db)?
            .as_str()
        {
            "Full" => EnrollmentType::Full,
            "Device" => EnrollmentType::Device,
            _ => return Err(Error::Conflict),
        },
        csr: row.try_get("csr").map_err(db)?,
        profile: row.try_get("profile").map_err(db)?,
        issuer: row.try_get("issuer").map_err(db)?,
        configuration: row.try_get("configuration").map_err(db)?,
        registration: uuid(&row, "registration")?,
        credential: uuid(&row, "credential")?,
        epoch: uuid(&row, "epoch")?,
        sealed: row.try_get("secrets").map_err(db)?,
    })
}

pub async fn issuance_intent(
    database: &crate::Store,
    windows: &Windows,
    auth: &Authorization,
    proof: &AuthorizedPrincipal,
    input: (&[u8], EnrollmentType),
    now: i64,
) -> Result<Intent, Error> {
    issuance_for_device(database, windows, auth, proof, input, None, now).await
}
pub(crate) async fn issuance_for_device(
    database: &crate::Store,
    windows: &Windows,
    auth: &Authorization,
    proof: &AuthorizedPrincipal,
    input: (&[u8], EnrollmentType),
    protocol_device: Option<&str>,
    now: i64,
) -> Result<Intent, Error> {
    issue_intent(
        database,
        windows,
        IssuanceAuthority::Password(auth, proof),
        input,
        protocol_device,
        now,
    )
    .await
}
pub(crate) async fn issue_intent(
    database: &crate::Store,
    windows: &Windows,
    authority: IssuanceAuthority<'_>,
    input: (&[u8], EnrollmentType),
    protocol_device: Option<&str>,
    now: i64,
) -> Result<Intent, Error> {
    let d = authority.coordinates();
    let (csr, enrollment_type) = input;
    if let Some(device) = protocol_device {
        rss_observation::Id::new(device).map_err(|_| Error::Malformed)?;
    }
    let verified = Csr::verify(csr)?;
    let mut tx = database.begin(&d.tenant).await?;
    let row = authority.current(&mut tx).await?;
    if row
        .try_get::<Option<String>, _>("windows_profile")
        .map_err(db)?
        .as_deref()
        != Some(enrollment_type.as_str())
    {
        return Err(Error::Forbidden);
    }
    if let Some(old) = crate::enrollment_store::intent(&mut tx, &d.tenant, d.id.to_string())
        .await
        .map_err(db)?
    {
        let old = intent(old)?;
        if protocol_device
            .is_some_and(|value| old.protocol_device.as_deref().unwrap_or(&d.device) != value)
            || old.enrollment_type != enrollment_type
            || old.csr != csr
            || old.configuration != windows.configuration
        {
            return Err(Error::Conflict);
        }
        return Ok(old);
    }
    rss_mdm_registration_service::admission::require_request_in(
        &mut tx,
        &d.tenant,
        d.id,
        rss_mdm_registration_service::quotas::Channel::WindowsMdm,
    )
    .await?;
    if row.try_get::<bool, _>("self_service").map_err(db)? && protocol_device.is_none() {
        return Err(Error::Malformed);
    }
    if row.try_get::<String, _>("state").map_err(db)? != "pending" {
        return Err(Error::Conflict);
    }
    let registration = Uuid::new_v4();
    let intent = Intent {
        protocol_device: protocol_device.map(str::to_owned),
        enrollment_type,
        csr: csr.to_vec(),
        profile: windows.ca.profile(&verified, registration, now)?.encode()?,
        issuer: windows.ca.der()?,
        configuration: windows.configuration.clone(),
        registration,
        credential: Uuid::new_v4(),
        epoch: Uuid::new_v4(),
        sealed: windows
            .protection
            .seal(&d.tenant, d.id, &protection::Secrets::generate()?)?,
    };
    authorize_profile(
        &mut tx,
        windows,
        &d.tenant,
        intent.credential,
        &intent.csr,
        &certificate::IssuanceProfile::decode(&intent.profile)?,
    )
    .await?;
    crate::enrollment_store::insert_intent(
        &mut tx,
        &d.tenant,
        crate::enrollment_store::NewIntent {
            request: d.id.to_string(),
            protocol_device: intent.protocol_device.as_deref(),
            csr: &intent.csr,
            profile: &intent.profile,
            issuer: &intent.issuer,
            configuration: &intent.configuration,
            registration: intent.registration.to_string(),
            credential: intent.credential.to_string(),
            epoch: intent.epoch.to_string(),
            secrets: &intent.sealed,
        },
    )
    .await
    .map_err(db)?;
    // An intent is not a completed enrollment. No success receipt/audit is published here.
    tx.commit().await.map_err(|_| Error::CommitUnknown)?;
    Ok(intent)
}
pub async fn issued_certificate(
    database: &crate::Store,
    tenant: &str,
    id: Uuid,
) -> Result<Option<Vec<u8>>, Error> {
    let mut tx = database.begin(tenant).await?;
    crate::enrollment_store::certificate(&mut tx, tenant, id.to_string())
        .await
        .map_err(db)
}
#[allow(
    clippy::too_many_arguments,
    reason = "explicit authorization, immutable intent and commit audit inputs"
)]
pub async fn complete_issuance(
    store: &rss_mdm_audit_integration::AuditStore,
    windows: &Windows,
    auth: &Authorization,
    proof: &AuthorizedPrincipal,
    intent: &Intent,
    certificate: &[u8],
    audit: &RequestAudit,
    now: i64,
    mount: &crate::device::ChannelMount,
    retirement: &dyn rss_mdm_registration_service::Retirement,
) -> Result<(), Error> {
    complete(
        store,
        windows,
        IssuanceAuthority::Password(auth, proof),
        intent,
        certificate,
        audit,
        now,
        mount,
        retirement,
    )
    .await
}
#[allow(
    clippy::too_many_arguments,
    reason = "single pipeline with live authority and immutable issuance evidence"
)]
pub(crate) async fn complete(
    store: &rss_mdm_audit_integration::AuditStore,
    windows: &Windows,
    authority: IssuanceAuthority<'_>,
    intent: &Intent,
    certificate: &[u8],
    audit: &RequestAudit,
    now: i64,
    mount: &crate::device::ChannelMount,
    retirement: &dyn rss_mdm_registration_service::Retirement,
) -> Result<(), Error> {
    let d = authority.coordinates();
    let profile = certificate::IssuanceProfile::decode(&intent.profile)?;
    let checked = windows.ca.validate_issued(
        &profile,
        &Csr::verify(&intent.csr)?,
        &[CertificateDer::from(certificate)],
        now,
    )?;
    let credential = mount.credential(checked.fingerprint())?;
    let digest =
        crate::enrollment::digest(&("enrollment_issue", d.id, &intent.csr, &intent.configuration));
    let operation = match authority {
        IssuanceAuthority::Native(admission) => Operation::from_admission(admission, &digest),
        IssuanceAuthority::Password(_, _) => Operation::from_coordinates(&d, &digest),
    };
    let budget = rss_mdm_audit_integration::budget::AuditBudget::retirement(None);
    let attempt = store
        .write(
            TenantId::parse(&d.tenant).map_err(|_| Error::Malformed)?,
            &budget.source_control(),
            (
                store,
                CompletionInputs {
                    retirement,
                    windows,
                    authority: &authority,
                    intent,
                    certificate,
                    credential: &credential,
                    operation: &operation,
                    audit,
                    facts: Vec::new(),
                },
            ),
            |(store, inputs), tx| {
                Box::pin(async move {
                    let replayed = tx
                        .with_connection_context(inputs, |inputs, c| {
                            Box::pin(complete_on(c, inputs))
                        })
                        .await?;
                    for fact in &inputs.facts {
                        store.append(tx, fact, false).await.map_err(Error::from)?;
                    }
                    let fact = rss_mdm_audit_integration::Fact::business(
                        inputs.audit,
                        &format!(
                            "enrollment_issue:{}:{}",
                            inputs.authority.coordinates().actor,
                            inputs.authority.coordinates().operation
                        ),
                        inputs.operation.digest().as_bytes(),
                        200,
                        "success",
                        Some(inputs.authority.coordinates().id),
                    )
                    .map_err(Error::from)?;
                    store
                        .append(tx, &fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        inputs.audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    inputs.audit.mark_commit_started();
                    Ok(())
                })
            },
        )
        .await;
    crate::operations::settle(attempt, audit)
}
struct CompletionInputs<'a> {
    retirement: &'a dyn rss_mdm_registration_service::Retirement,
    windows: &'a Windows,
    authority: &'a IssuanceAuthority<'a>,
    intent: &'a Intent,
    certificate: &'a [u8],
    credential: &'a VerifiedChannelCredential,
    operation: &'a Operation<'a>,
    audit: &'a RequestAudit,
    facts: Vec<rss_mdm_audit_integration::Fact>,
}
async fn complete_on(
    tx: &mut sqlx::PgConnection,
    inputs: &mut CompletionInputs<'_>,
) -> Result<bool, Error> {
    let CompletionInputs {
        retirement,
        windows,
        authority,
        intent,
        certificate,
        credential,
        operation,
        audit,
        facts,
    } = inputs;
    let windows = *windows;
    let authority = *authority;
    let d = authority.coordinates();
    let intent = *intent;
    let certificate = *certificate;
    let credential = *credential;
    let operation = *operation;
    let audit = *audit;
    let old = windows_receipts::replay(tx, operation).await?;
    let row = authority.current(tx).await?;
    if old.is_some() {
        crate::enrollment_store::active_windows_enrollment(tx, &d.tenant, d.id).await?;
        let old: Vec<u8> =
            crate::enrollment_store::required_certificate(tx, &d.tenant, d.id.to_string())
                .await
                .map_err(db)?;
        if old != certificate {
            return Err(Error::Conflict);
        }
        audit.registration(intent.registration);
        return Ok(true);
    }
    if row.try_get::<String, _>("state").map_err(db)? != "pending" {
        return Err(Error::Conflict);
    }
    let receipt = match authority {
        IssuanceAuthority::Password(_, proof) => {
            bind_in(
                tx,
                proof,
                credential,
                &BindRegistration {
                    operation_id: d.operation,
                    request_id: d.id,
                    expected_generation: d.expected_generation,
                    source: ReportSource::MdmWindows,
                },
                d.device.clone(),
                [intent.registration, intent.credential, intent.epoch],
                facts,
                *retirement,
            )
            .await?
        }
        IssuanceAuthority::Native(admission) => {
            crate::device::store::bind_native_in(
                tx,
                admission,
                credential,
                [intent.registration, intent.credential, intent.epoch],
                facts,
                *retirement,
            )
            .await?
        }
    };
    let secrets = windows.protection.open(&d.tenant, d.id, &intent.sealed)?;
    crate::enrollment_store::insert_certificate(
        tx,
        &d.tenant,
        d.id.to_string(),
        certificate,
        secrets.server_nonce.as_slice(),
    )
    .await
    .map_err(db)?;
    rss_mdm_pki_service::certificates::record_in(
        tx,
        &d.tenant,
        "windows",
        intent.registration,
        &rss_mdm_device_trust::digest(&intent.issuer),
        certificate,
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    // Evaluate again after channel/registration lock waits, immediately before committing.
    match authority {
        IssuanceAuthority::Password(auth, _) => {
            crate::enrollment::store::mark_bound_in(tx, &d.tenant, auth).await?
        }
        IssuanceAuthority::Native(p) => p.mark_bound_in(tx).await?,
    }
    audit.registration(receipt.registration);
    authority.check_live()?;
    windows_receipts::save(
        tx,
        operation,
        &serde_json::to_string(&receipt).expect("closed receipt"),
        audit,
    )
    .await?;
    Ok(false)
}

fn current(
    row: &sqlx::postgres::PgRow,
    auth: &Authorization,
    proof: &AuthorizedPrincipal,
) -> Result<(), Error> {
    auth.authorize(proof)?;
    if auth.source != rss_mdm_inventory::ReportSource::MdmWindows
        || row.try_get::<String, _>("state").map_err(db)? == "cancelled"
        || row.try_get::<bool, _>("self_service").map_err(db)? != auth.self_service
        || row.try_get::<i64, _>("password_version").map_err(db)? != auth.version
        || uuid(row, "credential_ref")? != auth.credential_ref
        || !row.try_get::<bool, _>("live").map_err(db)?
        || auth.actor != proof.principal_id()
        || auth.instance != proof.instance_id()
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub fn provision(
    w: &Windows,
    intent: &Intent,
    certificate: &[u8],
    auth: &Authorization,
    tenant: &str,
) -> Result<Vec<u8>, Error> {
    provision_request(w, intent, certificate, auth.id, tenant)
}
pub(crate) fn provision_request(
    w: &Windows,
    intent: &Intent,
    certificate: &[u8],
    request: Uuid,
    tenant: &str,
) -> Result<Vec<u8>, Error> {
    let secrets = w.protection.open(tenant, request, &intent.sealed)?;
    let subject = format!("CN={}", intent.registration);
    // SHA-1 is only the Windows certificate-store address; management authority uses SHA-256.
    let thumbprint = |bytes: &[u8]| -> String {
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    };
    rss_mdm_windows_mdm::provisioning::encode(
        &rss_mdm_windows_mdm::provisioning::Provisioning {
            poll: &w.poll,
            push_pfn: w.push.as_ref().map(|p| p.pfn.as_str()),
            enrollment_type: intent.enrollment_type,
            enterprise_device_id: &intent.registration.to_string(),
            authorities: &w.trust_certificates()?,
            certificate,
            certificate_thumbprint: &thumbprint(certificate),
            certificate_subject: &subject,
            management_url: &w.management_url(rss_mdm_registration_service::Purpose::Primary),
            renewal_discovery_url: &w
                .renewal_discovery_url(rss_mdm_registration_service::Purpose::Primary),
            provider_id: &w.provider_id,
            username: &intent.registration.to_string(),
            client_password: rss_mdm_windows_mdm::Secret(&secrets.client_password),
            server_password: rss_mdm_windows_mdm::Secret(&secrets.server_password),
            server_nonce: &secrets.server_nonce,
        },
        &rss_mdm_windows_mdm::CodecLimits::default(),
    )
    .map_err(|_| Error::Unavailable(Failure::Protocol))
}

use rss_mdm_audit_integration::RequestAudit;

pub(crate) async fn authorize_profile(
    c: &mut sqlx::PgConnection,
    w: &Windows,
    tenant: &str,
    attempt: Uuid,
    bytes: &[u8],
    profile: &certificate::IssuanceProfile,
) -> Result<(), Error> {
    let csr = Csr::verify(bytes)?;
    let pem = csr.pem()?;
    let issuer = profile
        .issuer
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let subject = profile.registration.to_string();
    let provider = w
        .providers
        .get(rss_mdm_agent_wire::pki::Purpose::Windows, &issuer)
        .map_err(|_| Error::Conflict)?;
    rss_mdm_pki_service::signing::authorize_in(
        c,
        Uuid::parse_str(tenant).map_err(|_| Error::Malformed)?,
        "windows",
        &issuer,
        provider,
        rss_mdm_pki_service::Sign {
            attempt,
            csr_pem: &pem,
            csr_digest: &csr.digest(),
            subject: &subject,
            sans: &[],
            start: profile.start,
            end: profile.end,
            deadline: profile.start + 60,
        },
    )
    .await
    .map_err(|_| Error::Conflict)
}

/// Dispatch once after the authorization owner has committed the immutable profile.
pub async fn sign(
    app: &HttpState,
    tenant: &str,
    intent: &Intent,
    now: i64,
) -> Result<Vec<u8>, Error> {
    let w = app.windows()?;
    let profile = certificate::IssuanceProfile::decode(&intent.profile)?;
    if profile.registration != intent.registration
        || profile.issuer != sha2::Sha256::digest(&intent.issuer).as_slice()
        || intent.configuration != w.configuration
    {
        return Err(Error::Conflict);
    }
    sign_profile(app, tenant, intent.credential, &intent.csr, &profile, now).await
}
pub(crate) async fn sign_profile(
    app: &HttpState,
    tenant: &str,
    attempt: Uuid,
    bytes: &[u8],
    profile: &certificate::IssuanceProfile,
    now: i64,
) -> Result<Vec<u8>, Error> {
    let w = app.windows()?;
    let csr = Csr::verify(bytes)?;
    let pem = csr.pem()?;
    let subject = profile.registration.to_string();
    let digest = csr.digest();
    let issuer = profile
        .issuer
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let provider = w
        .providers
        .get(rss_mdm_agent_wire::pki::Purpose::Windows, &issuer)
        .map_err(|_| Error::Conflict)?;
    let chain = rss_mdm_pki_service::signing::SigningStore::new(app.audit_store.clone())
        .issue(
            Uuid::parse_str(tenant).map_err(|_| Error::Malformed)?,
            ("windows", &issuer),
            provider,
            rss_mdm_pki_service::Sign {
                attempt,
                csr_pem: &pem,
                csr_digest: &digest,
                subject: &subject,
                sans: &[],
                start: profile.start,
                end: profile.end,
                deadline: profile.start + 60,
            },
            now,
            |chain| {
                let chain: Vec<_> = chain
                    .iter()
                    .map(|bytes| CertificateDer::from(bytes.as_slice()))
                    .collect();
                w.ca.validate_issued(profile, &csr, &chain, now).is_ok()
            },
        )
        .await
        .map_err(|_| Error::CommitUnknown)?;
    chain.into_iter().next().ok_or(Error::Conflict)
}
use sha2::Digest;

#[cfg(feature = "integration")]
pub mod fixture;
