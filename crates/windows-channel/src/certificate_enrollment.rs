//! Certificate enrollment stays on the management TLS origin; bootstrap never grants renewal.
//! ref: Microsoft CertificateStore CSP MY/WSTEP/Renew/ServerURL; MS-MDE2 certificate authentication.
use super::*;
use rss_mdm_registration_service::{DevicePrincipal, Purpose};

// Same standard service paths as bootstrap, mounted under a different TLS origin.
pub(super) fn router() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/EnrollmentServer/Discovery.svc",
            rss_mdm_http_contract::routing::external_get(
                discovery_probe,
                rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
            )
            .owned(
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            )
            .external_post(
                discover,
                rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
            )
            .owned(
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/EnrollmentServer/Policy.svc",
            rss_mdm_http_contract::routing::external_post(
                policy,
                rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
            )
            .owned(
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/EnrollmentServer/Enrollment.svc",
            rss_mdm_http_contract::routing::external_post(
                issue,
                rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
            )
            .owned(
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
        .route(
            "/EnrollmentServer/LinkedDiscovery.svc",
            rss_mdm_http_contract::routing::external_get(
                discovery_probe,
                rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
            )
            .owned(
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            )
            .external_post(
                linked_discover,
                rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
            )
            .owned(
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            ),
        )
}

async fn principal(
    app: &HttpState,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    purpose: Purpose,
) -> Result<DevicePrincipal, Error> {
    let Extension(peer) = peer.ok_or(Error::Unauthorized)?;
    let checked = app.windows()?.ca.verify(
        peer.chain(),
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let principal = app
        .devices
        .management_principal(
            &crate::device::ChannelMount::new(
                app.identity.tenant(),
                rss_mdm_inventory::ReportSource::MdmWindows,
                purpose,
            )
            .credential(checked.fingerprint())?,
        )
        .await?;
    if let Some((parent, _)) = principal.parent() {
        linked::current_parent(app, parent).await?;
    }
    Ok(principal)
}

pub(crate) async fn discover(
    State(app): State<Arc<HttpState>>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(endpoint): Extension<ManagementEndpoint>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    discovery(
        &app,
        peer,
        &endpoint.0,
        &headers,
        &bytes,
        Purpose::Primary,
        &audit,
    )
    .await
}

pub(crate) async fn linked_discover(
    State(app): State<Arc<HttpState>>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(endpoint): Extension<ManagementEndpoint>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    discovery(
        &app,
        peer,
        &endpoint.0,
        &headers,
        &bytes,
        Purpose::WindowsDeclared,
        &audit,
    )
    .await
}

async fn discovery(
    app: &HttpState,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    origin: &str,
    headers: &HeaderMap,
    bytes: &[u8],
    purpose: Purpose,
    audit: &RequestAudit,
) -> Response {
    let linked = purpose == Purpose::WindowsDeclared;
    let path = if linked {
        "/EnrollmentServer/LinkedDiscovery.svc"
    } else {
        "/EnrollmentServer/Discovery.svc"
    };
    let message = match decode_at(bytes, headers, Operation::Discover, origin, path) {
        Ok(message) => message,
        Err(error) => return fault(None, error),
    };
    let result = async {
        let principal = principal(app, peer, purpose).await?;
        audit.identify_device(principal.registration());
        audit.registration(principal.registration());
        audit.target_device(principal.device());
        let prefix = if linked { "Linked" } else { "" };
        response(
            Some(&message),
            Body::DiscoverResponse(soap::DiscoverResponse {
                auth_policy: soap::AuthPolicy::Certificate,
                enrollment_version: "4.0".into(),
                policy_url: format!("{origin}/EnrollmentServer/{prefix}Policy.svc"),
                enrollment_url: format!("{origin}/EnrollmentServer/{prefix}Enrollment.svc"),
            }),
            0,
        )
    }
    .await;
    result.unwrap_or_else(|error| fault(Some(&message), error))
}

pub(crate) async fn policy(
    State(app): State<Arc<HttpState>>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(endpoint): Extension<ManagementEndpoint>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let message = match decode_at(
        &bytes,
        &headers,
        Operation::GetPolicies,
        &endpoint.0,
        "/EnrollmentServer/Policy.svc",
    ) {
        Ok(message) => message,
        Err(error) => return fault(None, error),
    };
    policy_message(&app, peer, &audit, &message, Purpose::Primary)
        .await
        .unwrap_or_else(|error| fault(Some(&message), error))
}

pub(super) async fn policy_message(
    app: &HttpState,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    audit: &RequestAudit,
    message: &soap::Message,
    purpose: Purpose,
) -> Result<Response, Error> {
    validate_timestamp(
        message.header.security.as_ref(),
        app.clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?,
    )?;
    let principal = principal(app, peer, purpose).await?;
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    let linked = purpose == Purpose::WindowsDeclared;
    response(
        Some(message),
        Body::GetPoliciesResponse(soap::Policy {
            policy_id: if linked { "" } else { "RSS-MDM" }.into(),
            common_name: if linked {
                "RSS MDM WinDC"
            } else {
                "RSS MDM Device"
            }
            .into(),
            validity_seconds: rss_mdm_certificate::windows::RenewalPolicy::VALIDITY_SECONDS,
            renewal_seconds: rss_mdm_certificate::windows::RenewalPolicy::RENEW_SECONDS,
            minimum_key_length: 2048,
            major_revision: 1,
            minor_revision: 0,
        }),
        0,
    )
}

pub(crate) async fn issue(
    State(app): State<Arc<HttpState>>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    Extension(endpoint): Extension<ManagementEndpoint>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let message = match decode_at(
        &bytes,
        &headers,
        Operation::Issue,
        &endpoint.0,
        "/EnrollmentServer/Enrollment.svc",
    ) {
        Ok(message) => message,
        Err(error) => return fault(None, error),
    };
    let result = async {
        validate_timestamp(
            message.header.security.as_ref(),
            app.clock
                .unix_seconds()
                .ok_or(Error::Unavailable(Failure::Clock))?,
        )?;
        let Body::Issue(input) = &message.body else {
            return Err(Error::Malformed);
        };
        let soap::CertificateRequest::RenewalPkcs7(cms) = &input.request else {
            return Err(Error::Forbidden);
        };
        let _permit = app
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable(Failure::Capacity))?;
        let provisioning = renewal::issue(
            &app,
            &peer.ok_or(Error::Unauthorized)?.0,
            &cms.0,
            &audit,
            Purpose::Primary,
        )
        .await?;
        response(
            Some(&message),
            Body::IssueResponse(soap::IssueResponse {
                context: input.context.clone(),
                provisioning: Secret(provisioning),
                request_id: input.request_id.clone(),
                disposition: None,
            }),
            app.clock
                .unix_seconds()
                .ok_or(Error::Unavailable(Failure::Clock))?,
        )
    }
    .await;
    result.unwrap_or_else(|error| fault(Some(&message), error))
}
