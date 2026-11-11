//! Renewal discovery advertises public coordinates; XCEP and WSTEP require the current certificate.
//! ref: Microsoft CertificateStore CSP MY/WSTEP/Renew/ServerURL; MS-MDE2 certificate authentication.
use super::*;
use rss_mdm_registration_service::{DevicePrincipal, Purpose};

const RENEWAL_DISCOVERY: &str = "/EnrollmentServer/RenewalDiscovery.svc";
const LINKED_RENEWAL_DISCOVERY: &str = "/EnrollmentServer/LinkedRenewalDiscovery.svc";

pub(super) fn renewal_discovery_path(purpose: Purpose) -> &'static str {
    if purpose == Purpose::WindowsDeclared {
        LINKED_RENEWAL_DISCOVERY
    } else {
        RENEWAL_DISCOVERY
    }
}

pub(super) fn renewal_discovery_router()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    use rss_mdm_http_contract::{ExternalProtocol::WindowsMdm, module::Route, routing};
    rss_mdm_http_contract::route_module! { struct RenewalDiscoveryRoutes for [WindowsEnrollment] { get_primary, post_primary, get_linked, post_linked } }
    RenewalDiscoveryRoutes {
        get_primary: Route::new(
            RENEWAL_DISCOVERY,
            routing::external_get(
                discovery_probe,
                WindowsMdm,
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            ),
        ),
        post_primary: Route::new(
            RENEWAL_DISCOVERY,
            routing::external_post(
                renewal_discover,
                WindowsMdm,
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            ),
        ),
        get_linked: Route::new(
            LINKED_RENEWAL_DISCOVERY,
            routing::external_get(
                discovery_probe,
                WindowsMdm,
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            ),
        ),
        post_linked: Route::new(
            LINKED_RENEWAL_DISCOVERY,
            routing::external_post(
                linked_renewal_discover,
                WindowsMdm,
                &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action],
            ),
        ),
    }
    .assemble()
}

async fn renewal_discover(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    anonymous_discovery(&app, &headers, &bytes, Purpose::Primary)
}

async fn linked_renewal_discover(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    anonymous_discovery(&app, &headers, &bytes, Purpose::WindowsDeclared)
}

fn anonymous_discovery(
    app: &HttpState,
    headers: &HeaderMap,
    bytes: &[u8],
    purpose: Purpose,
) -> Response {
    let windows = match app.windows() {
        Ok(windows) => windows,
        Err(error) => return fault(None, error),
    };
    let message = match decode_at(
        bytes,
        headers,
        Operation::Discover,
        &windows.enrollment_origin,
        renewal_discovery_path(purpose),
    ) {
        Ok(message) => message,
        Err(error) => return fault(None, error),
    };
    discovery_response(&message, &windows.management_origin, purpose)
        .unwrap_or_else(|error| fault(Some(&message), error))
}

fn discovery_response(
    message: &soap::Message,
    origin: &str,
    purpose: Purpose,
) -> Result<Response, Error> {
    let prefix = if purpose == Purpose::WindowsDeclared {
        "Linked"
    } else {
        ""
    };
    response(
        Some(message),
        Body::DiscoverResponse(soap::DiscoverResponse {
            auth_policy: soap::AuthPolicy::Certificate,
            enrollment_version: "4.0".into(),
            policy_url: format!("{origin}/EnrollmentServer/{prefix}Policy.svc"),
            enrollment_url: format!("{origin}/EnrollmentServer/{prefix}Enrollment.svc"),
        }),
        0,
    )
}

// Same standard service paths as bootstrap, mounted under a different TLS origin.
pub(super) fn router()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RouterModule1 for [WindowsManagement] { external_get_discovery_probe, external_post_discover, external_post_policy, external_post_issue, external_get_discovery_probe_2, external_post_linked_discover } }
        RouterModule1 {
            external_get_discovery_probe: rss_mdm_http_contract::module::Route::new(
                "/EnrollmentServer/Discovery.svc",
                rss_mdm_http_contract::routing::external_get(
                    discovery_probe,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_post_discover: rss_mdm_http_contract::module::Route::new(
                "/EnrollmentServer/Discovery.svc",
                rss_mdm_http_contract::routing::external_post(
                    discover,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_post_policy: rss_mdm_http_contract::module::Route::new(
                "/EnrollmentServer/Policy.svc",
                rss_mdm_http_contract::routing::external_post(
                    policy,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_post_issue: rss_mdm_http_contract::module::Route::new(
                "/EnrollmentServer/Enrollment.svc",
                rss_mdm_http_contract::routing::external_post(
                    issue,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_get_discovery_probe_2: rss_mdm_http_contract::module::Route::new(
                "/EnrollmentServer/LinkedDiscovery.svc",
                rss_mdm_http_contract::routing::external_get(
                    discovery_probe,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_post_linked_discover: rss_mdm_http_contract::module::Route::new(
                "/EnrollmentServer/LinkedDiscovery.svc",
                rss_mdm_http_contract::routing::external_post(
                    linked_discover,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
        }
        .assemble()
    }
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
                rss_mdm_install_support::StorageProfile::Mdm,
                app.identity.tenant(),
                rss_mdm_inventory::ReportSource::MdmWindows,
                purpose,
            )
            .credential(checked.fingerprint())?,
        )
        .await?;
    if principal.purpose() == rss_mdm_registration_service::Purpose::WindowsDeclared {
        linked::current_parent(app, principal.device()).await?;
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
        audit.identify_device(principal.device());
        audit.target_device(principal.device());
        discovery_response(&message, origin, purpose)
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
    audit.identify_device(principal.device());
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
