use super::*;
pub(crate) async fn enrollment(
    app: &HttpState,
    message: &rss_mdm_windows_mdm::soap::Message,
    a: &RequestAudit,
    issuing: bool,
    token: &[u8],
) -> Result<axum::response::Response, Error> {
    use rss_mdm_windows_mdm::{Secret, soap};
    if token.is_empty() || token.len() > 32768 {
        return Err(Error::Unauthorized);
    }
    let token = Zeroizing::new(
        std::str::from_utf8(token)
            .map_err(|_| Error::Unauthorized)?
            .to_owned(),
    );
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(crate::Failure::Clock))?;
    let _permit = app
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Unavailable(crate::Failure::Capacity))?;
    if !issuing {
        let entra = owner(app)?;
        let subject = entra.verify(token).await?;
        let mut tx = app.access.begin_read(&entra.tenant.to_string()).await?;
        let settings = settings_in(&mut tx, &entra.tenant.to_string(), false).await?;
        settings
            .policy
            .permits(subject.claims().map_err(|_| Error::Unauthorized)?.user)?;
        subject.check_live().map_err(|_| Error::Unauthorized)?;
        return crate::response(
            Some(message),
            soap::Body::GetPoliciesResponse(soap::Policy {
                policy_id: "RSS-MDM".into(),
                common_name: "RSS MDM Device".into(),
                validity_seconds: rss_mdm_certificate::windows::RenewalPolicy::VALIDITY_SECONDS,
                renewal_seconds: rss_mdm_certificate::windows::RenewalPolicy::RENEW_SECONDS,
                minimum_key_length: 2048,
                major_revision: 1,
                minor_revision: 0,
            }),
            now,
        );
    }
    a.intent(rss_mdm_audit_integration::AuditIntent::Management);
    a.require_final_request();
    let soap::Body::Issue(input) = &message.body else {
        return Err(Error::Malformed);
    };
    let soap::CertificateRequest::Pkcs10(csr) = &input.request else {
        return Err(Error::Unsupported);
    };
    crate::certificate::Csr::verify(&csr.0)?;
    let context = |key| {
        input
            .additional_context
            .0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let (profile, enrollment_type) = match context("EnrollmentType") {
        Some("Device") => (
            WindowsProfile::Device,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Device,
        ),
        Some("Full") => (
            WindowsProfile::Full,
            rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        ),
        _ => return Err(Error::Malformed),
    };
    let admission = admit(app, token, context("EnrollmentData"), &csr.0, profile, a).await?;
    let d = admission.coordinates();
    let intent = crate::issuance::issue_intent(
        &app.audit_store,
        &app.access,
        app.windows()?,
        crate::issuance::IssuanceAuthority::Native(&admission),
        (&csr.0, enrollment_type),
        context("DeviceID"),
        now,
    )
    .await?;
    let certificate = crate::issuance::sign(app, &d.tenant, &intent, now).await?;
    let provisioning =
        crate::issuance::provision_request(app.windows()?, &intent, &certificate, d.id, &d.tenant)?;
    // Identity recheck runs before the final MDM transaction and never under its locks.
    let admission = admission.recheck_entra(&owner(app)?.authority).await?;
    crate::issuance::complete(
        &app.audit_store,
        app.windows()?,
        crate::issuance::IssuanceAuthority::Native(&admission),
        &intent,
        &certificate,
        a,
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(crate::Failure::Clock))?,
        &app.mount,
        app.devices.retirement(),
    )
    .await?;
    crate::response(
        Some(message),
        soap::Body::IssueResponse(soap::IssueResponse {
            context: input.context.clone(),
            provisioning: Secret(provisioning),
            request_id: Some(soap::NillableText::Value(Secret(
                admission.coordinates().id.to_string(),
            ))),
            disposition: None,
        }),
        now,
    )
}
