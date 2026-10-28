//! Standard Windows enrollment using a short handoff from a started Agent task.
use crate::{Error, Failure, HttpState};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_windows_mdm::{Secret, soap};
use uuid::Uuid;
pub(crate) async fn try_enrollment(
    app: &HttpState,
    id: Uuid,
    password: &crate::enrollment::Password,
    message: &soap::Message,
    audit: &RequestAudit,
    issuing: bool,
) -> Result<Option<axum::response::Response>, Error> {
    let tenant = app.identity.tenant().to_string();
    let store = app.access.registration();
    let mut tx = app.access.begin_read(&tenant).await?;
    let kind: Option<String> = sqlx::query_scalar(
        "SELECT authority_kind FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(&tenant)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(crate::database::db)?;
    tx.rollback().await.map_err(crate::database::db)?;
    if kind.as_deref() != Some("agent_policy") {
        return Ok(None);
    }
    let admission = rss_mdm_registration_service::enrollment::native::agent_policy(
        &store,
        &tenant,
        id,
        Some(password.expose()),
        app.execution.clone(),
    )
    .await?;
    if admission.coordinates().source != rss_mdm_inventory::ReportSource::MdmWindows {
        return Err(Error::Unauthorized);
    }
    admission.bind_audit(audit)?;
    let now = app
        .clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))?;
    if let Some(timestamp) = message
        .header
        .security
        .as_ref()
        .and_then(|s| s.timestamp.as_ref())
    {
        let parse = |s: &str| {
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                .map(|t| t.unix_timestamp())
                .map_err(|_| Error::Malformed)
        };
        let (created, expires) = (parse(&timestamp.created)?, parse(&timestamp.expires)?);
        if created > now + 30
            || created < now - 300
            || expires <= now
            || expires <= created
            || expires - created > 300
        {
            return Err(Error::Unauthorized);
        }
    }
    if !issuing {
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
        )
        .map(Some);
    }
    audit.require_final_request();
    audit.operation(
        admission.coordinates().operation,
        "enrollment_issue",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let soap::Body::Issue(input) = &message.body else {
        return Err(Error::Malformed);
    };
    let soap::CertificateRequest::Pkcs10(csr) = &input.request else {
        return Err(Error::Unsupported);
    };
    let context = |key| {
        input
            .additional_context
            .0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let profile = match context("EnrollmentType") {
        Some("Full") => rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        Some("Device") => rss_mdm_windows_mdm::provisioning::EnrollmentType::Device,
        _ => return Err(Error::Malformed),
    };
    let intent = crate::issuance::issue_intent(
        &app.access,
        app.windows()?,
        crate::issuance::IssuanceAuthority::Native(&admission),
        (&csr.0, profile),
        context("DeviceID"),
        now,
    )
    .await?;
    let certificate = crate::issuance::sign(app, &tenant, &intent, now).await?;
    let provisioning =
        crate::issuance::provision_request(app.windows()?, &intent, &certificate, id, &tenant)?;
    crate::issuance::complete(
        &app.audit_store,
        app.windows()?,
        crate::issuance::IssuanceAuthority::Native(&admission),
        &intent,
        &certificate,
        audit,
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
        &app.mount,
        app.devices.retirement(),
    )
    .await?;
    crate::response(
        Some(message),
        soap::Body::IssueResponse(soap::IssueResponse {
            context: input.context.clone(),
            provisioning: Secret(provisioning),
            request_id: Some(soap::NillableText::Value(Secret(id.to_string()))),
            disposition: None,
        }),
        now,
    )
    .map(Some)
}
