//! Current Windows credential state for downstream integration consumers.
use super::*;

pub fn intent(
    w: &Windows,
    tenant: &str,
    request: Uuid,
    csr: &[u8],
    enrollment_type: EnrollmentType,
    now: i64,
) -> Result<Intent, Error> {
    let verified = Csr::verify(csr)?;
    let registration = Uuid::new_v4();
    Ok(Intent {
        protocol_device: None,
        enrollment_type,
        csr: csr.to_vec(),
        profile: w.ca.profile(&verified, registration, now)?.encode()?,
        issuer: w.ca.der()?,
        configuration: w.configuration.clone(),
        registration,
        credential: Uuid::new_v4(),
        epoch: Uuid::new_v4(),
        sealed: w
            .protection
            .seal(tenant, request, &protection::Secrets::generate()?)?,
    })
}

pub struct Seed<'a> {
    pub request: Uuid,
    pub device: &'a str,
    pub intent: &'a Intent,
    pub certificate: &'a [u8],
    pub now: i64,
}
pub async fn current_in(
    c: &mut sqlx::PgConnection,
    w: &Windows,
    proof: &AuthorizedPrincipal,
    seed: Seed<'_>,
) -> Result<(crate::enrollment::Receipt, Vec<u8>), Error> {
    let tenant = proof.tenant_id();
    let i = seed.intent;
    let profile = certificate::IssuanceProfile::decode(&i.profile)?;
    if profile.registration != i.registration
        || i.configuration != w.configuration
        || i.issuer != w.ca.der()?
    {
        return Err(Error::Conflict);
    }
    let checked = w.ca.validate_issued(
        &profile,
        &Csr::verify(&i.csr)?,
        &[CertificateDer::from(seed.certificate)],
        seed.now,
    )?;
    let mount = crate::device::ChannelMount::new(
        TenantId::parse(tenant).map_err(|_| Error::Malformed)?,
        ReportSource::MdmWindows,
        rss_mdm_registration_service::Purpose::Primary,
    );
    let credential = mount.credential(checked.fingerprint())?;
    let receipt = rss_mdm_registration_service::device::fixture::native_in(
        c,
        proof,
        &credential,
        rss_mdm_registration_service::device::fixture::NativeSeed {
            device: seed.device,
            request: seed.request,
            ids: [i.registration, i.credential, i.epoch],
            windows_profile: Some(match i.enrollment_type {
                EnrollmentType::Full => {
                    rss_mdm_registration_service::enrollment::WindowsProfile::Full
                }
                EnrollmentType::Device => {
                    rss_mdm_registration_service::enrollment::WindowsProfile::Device
                }
            }),
        },
    )
    .await?;
    crate::enrollment_store::insert_intent(
        c,
        tenant,
        crate::enrollment_store::NewIntent {
            request: seed.request.to_string(),
            protocol_device: i.protocol_device.as_deref(),
            csr: &i.csr,
            profile: &i.profile,
            issuer: &i.issuer,
            configuration: &i.configuration,
            registration: i.registration.to_string(),
            credential: i.credential.to_string(),
            epoch: i.epoch.to_string(),
            secrets: &i.sealed,
        },
    )
    .await
    .map_err(db)?;
    let secrets = w.protection.open(tenant, seed.request, &i.sealed)?;
    crate::enrollment_store::insert_certificate(
        c,
        tenant,
        seed.request.to_string(),
        seed.certificate,
        &secrets.server_nonce,
    )
    .await
    .map_err(db)?;
    rss_mdm_pki_service::certificates::record_in(
        c,
        tenant,
        "windows",
        i.registration,
        &rss_mdm_device_trust::digest(&i.issuer),
        seed.certificate,
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    Ok((
        receipt,
        provision_request(w, i, seed.certificate, seed.request, tenant)?,
    ))
}

/// Observe protocol-issued state without authorizing or synthesizing an enrollment.
pub async fn observed(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: Uuid,
) -> Result<(Intent, Vec<u8>), Error> {
    let row = crate::enrollment_store::intent(c, tenant, request.to_string())
        .await
        .map_err(db)?
        .ok_or(Error::Conflict)?;
    let intent = super::intent(row)?;
    let certificate = crate::enrollment_store::required_certificate(c, tenant, request.to_string())
        .await
        .map_err(db)?;
    Ok((intent, certificate))
}
