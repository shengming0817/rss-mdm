//! Certificate-only WinDC discovery and independent enrollment, bound to the live parent.
//! ref: Microsoft declared-configuration-{discovery,enrollment}; MS-MDE2 certificate authentication.
use super::*;
use crate::database::db;
use rss_mdm_registration_service::{DevicePrincipal, Purpose};
use serde::Deserialize;
use sqlx::Row;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Discovery {
    user_domain: Option<String>,
    upn: Option<String>,
    tenant_id: Option<String>,
    emm_device_id: Option<String>,
    enrollment_type: String,
    os_version: String,
}
fn now(app: &HttpState) -> Result<i64, Error> {
    app.clock
        .unix_seconds()
        .ok_or(Error::Unavailable(Failure::Clock))
}
pub(crate) async fn discover(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    bytes: Bytes,
) -> Result<Response, Error> {
    if uri.query() != Some("api-version=1.0")
        || headers.get_all("content-type").iter().count() != 1
        || !headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
            })
    {
        return Err(Error::Malformed);
    }
    let d: Discovery = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
    if d.enrollment_type != "User" {
        return Err(Error::Unsupported);
    }
    for value in [&d.user_domain, &d.upn, &d.tenant_id, &d.emm_device_id]
        .into_iter()
        .flatten()
    {
        if value.len() > 2048 || value.chars().any(char::is_control) {
            return Err(Error::Malformed);
        }
    }
    let build: [u32; 4] = d
        .os_version
        .split('.')
        .map(|v| v.parse::<u32>().map_err(|_| Error::Malformed))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| Error::Malformed)?;
    if !rss_mdm_windows_mdm::native::declared::certificate_supported(build) {
        return Err(Error::Unsupported);
    }
    let origin = &app.windows()?.enrollment_origin;
    // Discovery claims only select the protocol. They never create registration authority.
    Ok(axum::Json(serde_json::json!({"EnrollmentServiceUrl":format!("{origin}/EnrollmentServer/LinkedEnrollment.svc"),"EnrollmentPolicyServiceUrl":format!("{origin}/EnrollmentServer/LinkedPolicy.svc"),"AuthenticationServiceUrl":format!("{origin}/EnrollmentServer/LinkedEnrollment.svc"),"EnrollmentVersion":"5.0","AuthPolicy":"Certificate"})).into_response())
}
pub(crate) async fn policy(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, Error> {
    let message = decode(
        &bytes,
        &headers,
        Operation::GetPolicies,
        &app,
        "/EnrollmentServer/LinkedPolicy.svc",
    )?;
    let security = message.header.security.as_ref().ok_or(Error::Malformed)?;
    if security.certificate.is_none() || security.username.is_some() {
        return Err(Error::Unsupported);
    }
    // XCEP is policy retrieval. Exported BST possession is not parent authentication.
    response(
        Some(&message),
        Body::GetPoliciesResponse(soap::Policy {
            policy_id: "".into(),
            common_name: "RSS MDM WinDC".into(),
            validity_seconds: 90 * 86400,
            renewal_seconds: 30 * 86400,
            minimum_key_length: 2048,
            major_revision: 1,
            minor_revision: 0,
        }),
        now(&app)?,
    )
}
pub(crate) async fn current_parent(app: &HttpState, parent: Uuid) -> Result<(), Error> {
    let mut c = app
        .access
        .begin_read(&app.identity.tenant().to_string())
        .await?;
    let certificate: Vec<u8> = sqlx::query_scalar("SELECT material.certificate FROM mdm_access.registrations r JOIN mdm_access.credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) JOIN LATERAL (SELECT e.certificate FROM mdm_access.enrollment_certificates e WHERE e.tenant_id=r.tenant_id AND e.request_id=r.request_id UNION ALL SELECT n.certificate FROM mdm_windows.renewals n WHERE n.tenant_id=r.tenant_id AND n.registration=r.id AND n.activated_at IS NOT NULL) material ON encode(sha256(material.certificate),'hex')=k.locator WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.purpose='primary' AND r.state='active' AND k.state='active'")
        .bind(app.identity.tenant().to_string()).bind(parent).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
    app.windows()?.ca.verify(&[certificate.into()], now(app)?)?;
    Ok(())
}
pub(crate) async fn issue(
    State(app): State<Arc<HttpState>>,
    peer: Option<Extension<rss_mdm_certificate::HandshakePeer>>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, Error> {
    let message = decode(
        &bytes,
        &headers,
        Operation::Issue,
        &app,
        "/EnrollmentServer/LinkedEnrollment.svc",
    )?;
    let Body::Issue(input) = &message.body else {
        return Err(Error::Malformed);
    };
    if let soap::CertificateRequest::RenewalPkcs7(cms) = &input.request {
        let provision = crate::renewal::issue(
            &app,
            &peer.ok_or(Error::Unauthorized)?.0,
            &cms.0,
            &audit,
            Purpose::WindowsDeclared,
        )
        .await?;
        return response(
            Some(&message),
            Body::IssueResponse(soap::IssueResponse {
                context: input.context.clone(),
                provisioning: Secret(provision),
                request_id: input.request_id.clone(),
                disposition: None,
            }),
            now(&app)?,
        );
    }
    let proof = app.windows()?.ca.linked_proof(&bytes, now(&app)?)?;
    let parent = app
        .devices
        .management_principal(
            &crate::device::ChannelMount::new(
                app.identity.tenant(),
                rss_mdm_inventory::ReportSource::MdmWindows,
                Purpose::Primary,
            )
            .credential(proof.fingerprint()),
        )
        .await?;
    let operation = message
        .header
        .message_id
        .as_deref()
        .and_then(|v| v.strip_prefix("urn:uuid:"))
        .and_then(|v| Uuid::parse_str(v).ok())
        .filter(|v| !v.is_nil())
        .ok_or(Error::Malformed)?;
    if input
        .additional_context
        .0
        .iter()
        .any(|(k, v)| k == "DeviceID" && v != parent.device())
    {
        return Err(Error::Forbidden);
    }
    audit.identify_device(parent.registration());
    audit.registration(parent.registration());
    audit.target(parent.device());
    audit.operation(operation, "enrollment_issue");
    let soap::CertificateRequest::Pkcs10(csr) = &input.request else {
        return Err(Error::Malformed);
    };
    let (id, intent) = intent(&app, &parent, operation, proof.replay(), &csr.0, input).await?;
    let certificate = if let Some(certificate) =
        issuance::issued_certificate(&app.access, &parent.tenant().to_string(), id).await?
    {
        certificate
    } else {
        app.windows()?.ca.sign(&app.windows()?.ca.restore_intent(
            &intent.tbs,
            &certificate::Csr::verify(&intent.csr)?,
            intent.registration,
        )?)?
    };
    complete(
        &app,
        &parent,
        id,
        &intent,
        &certificate,
        &audit,
        proof.replay(),
    )
    .await?;
    let secrets =
        app.windows()?
            .protection
            .open(&parent.tenant().to_string(), id, &intent.sealed)?;
    let thumbprint = |b: &[u8]| {
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, b)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    };
    use x509_cert::der::Decode;
    let subject = x509_cert::TbsCertificate::from_der(&intent.tbs)
        .map_err(|_| Error::Conflict)?
        .subject
        .to_string();
    let w = app.windows()?;
    let provision = rss_mdm_windows_mdm::provisioning::encode(
        &rss_mdm_windows_mdm::provisioning::Provisioning {
            poll: &w.poll,
            push_pfn: None,
            enrollment_type: intent.enrollment_type,
            enterprise_device_id: &parent.device().to_owned(),
            issuer: &intent.issuer,
            certificate: &certificate,
            issuer_thumbprint: &thumbprint(&intent.issuer),
            certificate_thumbprint: &thumbprint(&certificate),
            certificate_subject: &subject,
            management_url: &w.management_url(Purpose::WindowsDeclared),
            provider_id: &w.provider(Purpose::WindowsDeclared),
            username: &intent.registration.to_string(),
            client_password: Secret(&secrets.client_password),
            server_password: Secret(&secrets.server_password),
            server_nonce: &secrets.server_nonce,
        },
        &CodecLimits::default(),
    )
    .map_err(|_| Error::Malformed)?;
    response(
        Some(&message),
        Body::IssueResponse(soap::IssueResponse {
            context: input.context.clone(),
            provisioning: Secret(provision),
            request_id: input.request_id.clone(),
            disposition: None,
        }),
        now(&app)?,
    )
}
async fn intent(
    app: &HttpState,
    parent: &DevicePrincipal,
    operation: Uuid,
    digest: [u8; 32],
    csr: &[u8],
    input: &soap::Issue,
) -> Result<(Uuid, issuance::Intent), Error> {
    let w = app.windows()?;
    let verified = certificate::Csr::verify(csr)?;
    let tenant = parent.tenant().to_string();
    let mut c = app.access.begin(&tenant).await?;
    crate::device::store::revalidate_management(&mut c, parent).await?;
    if let Some(row) = sqlx::query("SELECT request_id,digest,parent_id,parent_generation,parent_credential FROM mdm_windows.linked_enrollments WHERE tenant_id=$1::uuid AND id=$2")
        .bind(&tenant).bind(operation).fetch_optional(&mut *c).await.map_err(db)? {
        if row.try_get::<Vec<u8>,_>("digest").map_err(db)?.as_slice()!=digest || row.try_get::<Uuid,_>("parent_id").map_err(db)?!=parent.registration() || row.try_get::<i64,_>("parent_generation").map_err(db)?!=parent.generation() || row.try_get::<Uuid,_>("parent_credential").map_err(db)?!=parent.credential() { return Err(Error::Conflict); }
        let id: Uuid = row.try_get("request_id").map_err(db)?;
        let row = enrollment_store::intent(&mut c,&tenant,id.to_string()).await.map_err(db)?.ok_or(Error::Conflict)?;
        let intent = issuance::intent(row)?;
        if intent.csr!=csr || intent.issuer!=w.ca.der() || intent.configuration!=w.configuration { return Err(Error::Conflict); }
        return Ok((id,intent));
    }
    let id = Uuid::new_v4();
    crate::device::linked::request_in(&mut c, parent, id, operation).await?;
    let profile: String = sqlx::query_scalar(
        "SELECT windows_profile FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(&tenant)
    .bind(id)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if input
        .additional_context
        .0
        .iter()
        .any(|(k, v)| k == "EnrollmentType" && v != &profile)
    {
        return Err(Error::Forbidden);
    }
    let enrollment_type = match profile.as_str() {
        "Full" => rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
        "Device" => rss_mdm_windows_mdm::provisioning::EnrollmentType::Device,
        _ => return Err(Error::Forbidden),
    };
    let registration = Uuid::new_v4();
    let intent = issuance::Intent {
        enrollment_type,
        csr: csr.to_vec(),
        tbs: w
            .ca
            .intent(&verified, registration, now(app)?)?
            .as_der()
            .to_vec(),
        issuer: w.ca.der().to_vec(),
        configuration: w.configuration.clone(),
        registration,
        credential: Uuid::new_v4(),
        epoch: Uuid::new_v4(),
        sealed: w
            .protection
            .seal(&tenant, id, &protection::Secrets::generate()?)?,
    };
    enrollment_store::insert_intent(
        &mut c,
        &tenant,
        enrollment_store::NewIntent {
            request: id.to_string(),
            csr: &intent.csr,
            tbs: &intent.tbs,
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
    sqlx::query("INSERT INTO mdm_windows.linked_enrollments(tenant_id,id,parent_id,parent_generation,parent_credential,request_id,digest) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)")
        .bind(&tenant).bind(operation).bind(parent.registration()).bind(parent.generation()).bind(parent.credential()).bind(id).bind(digest.as_slice()).execute(&mut *c).await.map_err(db)?;
    c.commit().await.map_err(|_| Error::CommitUnknown)?;
    Ok((id, intent))
}
async fn complete(
    app: &HttpState,
    parent: &DevicePrincipal,
    id: Uuid,
    intent: &issuance::Intent,
    certificate: &[u8],
    audit: &RequestAudit,
    digest: [u8; 32],
) -> Result<(), Error> {
    use x509_cert::der::{Decode, Encode};
    if x509_cert::Certificate::from_der(certificate)
        .map_err(|_| Error::Conflict)?
        .tbs_certificate
        .to_der()
        .map_err(|_| Error::Conflict)?
        != intent.tbs
    {
        return Err(Error::Conflict);
    }
    let leaf = app.windows()?.ca.verify(&[certificate.into()], now(app)?)?;
    let credential = crate::device::ChannelMount::new(
        parent.tenant(),
        rss_mdm_inventory::ReportSource::MdmWindows,
        Purpose::WindowsDeclared,
    )
    .credential(leaf.fingerprint());
    let budget = app.devices.retirement_budget();
    let control = budget.control();
    let result = app.audit_store.write(parent.tenant(),&control,(app,parent,id,intent,certificate,audit,&credential,digest,Vec::new()),|(app,parent,id,intent,certificate,audit,credential,digest,facts),tx|Box::pin(async move {
        let replayed = tx.with_connection_context(&mut (*app,*parent,*id,*intent,*certificate,*credential,&mut *facts),|(app,parent,id,intent,certificate,credential,facts),c|Box::pin(async move {
            let (app,parent,id,intent,certificate,credential) = (*app,*parent,*id,*intent,*certificate,*credential);
            crate::device::store::revalidate_management(c,parent).await?;
            if let Some(old) = enrollment_store::certificate(c,&parent.tenant().to_string(),id.to_string()).await.map_err(db)? {
                let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND state='active' AND purpose='windows_declared' AND parent_id=$3 AND parent_generation=$4)")
                    .bind(parent.tenant().to_string()).bind(intent.registration).bind(parent.registration()).bind(parent.generation()).fetch_one(c).await.map_err(db)?;
                if !live || old != certificate { return Err(Error::Conflict); } return Ok(true);
            }
            crate::device::linked::bind_in(c,parent,credential,id,[intent.registration,intent.credential,intent.epoch],facts,app.devices.retirement()).await?;
            let secrets = app.windows()?.protection.open(&parent.tenant().to_string(),id,&intent.sealed)?;
            enrollment_store::insert_certificate(c,&parent.tenant().to_string(),id.to_string(),certificate,&secrets.server_nonce).await.map_err(db)?;
            Ok(false)
        })).await?;
        for fact in facts.iter() { app.audit_store.append(tx,fact,false).await.map_err(Error::from)?; }
        let fact = rss_mdm_audit_integration::Fact::business(audit,&format!("windows-linked:{id}:issued"),digest,200,"success",Some(*id)).map_err(Error::from)?;
        app.audit_store.append(tx,&fact,replayed).await.map_err(Error::from)?;
        audit.mark_commit_started(); Ok(())
    })).await;
    crate::operations::settle(result, audit)
}
