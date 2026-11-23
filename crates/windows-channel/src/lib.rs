//! Windows enrollment and management protocol boundary.
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
mod certificate_enrollment;
pub mod certificate_queries;
mod database;
pub mod enrollment_store;
pub mod entra;
pub mod issuance;
mod linked;
pub mod management;
mod native;
mod operations;
pub mod participants;
mod protection;
mod protocol_device;
pub mod protocol_types;
pub mod push;
mod push_channel;
mod push_worker;
mod renewal;
pub mod results;
pub mod retention;
pub mod runtime_materials;
mod unenrollment;
pub mod wns_materials;
pub use database::Store;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure};
mod error;
pub use error::{Error, Missing};
use rss_mdm_authorization_service as authorization;
use rss_mdm_registration_service::{device, enrollment};
mod agent_collection;
mod agent_enrollment;
mod collection;
pub mod collection_plan;
mod large_object;
mod notifications;
mod transcript;
mod trust_installation;
use axum::{
    Extension,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use enrollment::Password;
use rss_mdm_certificate::windows as certificate;
use rss_mdm_http_contract::Router;
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    soap::{self, Body, Operation},
};
use std::sync::Arc;
use uuid::Uuid;

pub struct Windows {
    pub entra: Option<Arc<entra::Entra>>,
    pub poll: rss_mdm_windows_mdm::provisioning::Poll,
    pub push: Option<Arc<push::Push>>,
    pub additional_management_origins: Vec<String>,
    pub enrollment_origin: String,
    pub management_origin: String,
    pub provider_id: String,
    pub ca: rss_mdm_device_trust::windows::WindowsDeviceTrust,
    pub providers: Arc<rss_mdm_pki_service::providers::Providers>,
    protection: protection::Protection,
    configuration: String,
}
/// Canonical stable protocol identity, shared by runtime construction and controlled upgrade.
pub fn protocol_identity(
    enrollment_origin: &str,
    management_origin: &str,
    provider_id: &str,
    protector: &rss_mdm_native_protection::Protector,
    poll: &rss_mdm_windows_mdm::provisioning::Poll,
) -> Result<String, Error> {
    poll.validate().map_err(|_| Error::Malformed)?;
    Ok(enrollment::digest(&(
        "mdm.windows.profile.v1",
        "separate-bootstrap-and-certificate-enrollment",
        poll,
        enrollment_origin,
        management_origin,
        provider_id,
        protector.fingerprint_id(),
    )))
}
impl Windows {
    /// Canonical OnPremise username for the system enrollment instructions.
    pub fn enrollment_username(&self, enrollment: Uuid) -> Result<String, Error> {
        let origin: axum::http::Uri = self
            .enrollment_origin
            .parse()
            .map_err(|_| Error::Malformed)?;
        let host = origin.host().ok_or(Error::Malformed)?;
        Ok(format!("{enrollment}@{host}"))
    }

    pub fn new(
        enrollment_origin: String,
        management_origin: String,
        provider_id: String,
        ca: rss_mdm_device_trust::windows::WindowsDeviceTrust,
        providers: Arc<rss_mdm_pki_service::providers::Providers>,
        protector: Arc<rss_mdm_native_protection::Protector>,
        poll: rss_mdm_windows_mdm::provisioning::Poll,
    ) -> Result<Self, Error> {
        poll.validate().map_err(|_| Error::Malformed)?;
        let configuration = protocol_identity(
            &enrollment_origin,
            &management_origin,
            &provider_id,
            &protector,
            &poll,
        )?;
        Ok(Self {
            entra: None,
            poll,
            push: None,
            additional_management_origins: Vec::new(),
            enrollment_origin,
            management_origin,
            provider_id,
            ca,
            providers,
            protection: protection::Protection::new(protector),
            configuration,
        })
    }
    pub fn trust_certificates(
        &self,
    ) -> Result<Vec<rss_mdm_windows_mdm::provisioning::AuthorityCertificate>, Error> {
        use rss_mdm_windows_mdm::provisioning::{AuthorityCertificate, AuthorityStore};
        let mut certificates = Vec::new();
        for (root, certificate) in self.ca.trust.certificates().map_err(|_| Error::Conflict)? {
            let thumbprint =
                ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &certificate)
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect();
            certificates.push(AuthorityCertificate {
                store: if root {
                    AuthorityStore::Root
                } else {
                    AuthorityStore::Intermediate
                },
                certificate,
                thumbprint,
            });
        }
        Ok(certificates)
    }
    pub fn provider(
        &self,
        purpose: rss_mdm_registration_service::Purpose,
    ) -> Result<String, Error> {
        match purpose {
            rss_mdm_registration_service::Purpose::Primary => Ok(self.provider_id.clone()),
            rss_mdm_registration_service::Purpose::WindowsDeclared => {
                Ok(format!("{}-declared", self.provider_id))
            }
            rss_mdm_registration_service::Purpose::DaDevice => Err(Error::Forbidden),
        }
    }
    pub fn management_urls(&self, purpose: rss_mdm_registration_service::Purpose) -> Vec<String> {
        std::iter::once(&self.management_origin)
            .chain(&self.additional_management_origins)
            .map(|origin| {
                format!(
                    "{origin}/ManagementServer/{}.svc",
                    if purpose == rss_mdm_registration_service::Purpose::Primary {
                        "MDM"
                    } else {
                        "Declared"
                    }
                )
            })
            .collect()
    }
    /// Windows starts ROBO with anonymous discovery, then authenticates at XCEP and WSTEP.
    pub fn renewal_discovery_url(&self, purpose: rss_mdm_registration_service::Purpose) -> String {
        format!(
            "{}{}",
            self.enrollment_origin,
            certificate_enrollment::renewal_discovery_path(purpose),
        )
    }
    pub fn management_url(&self, purpose: rss_mdm_registration_service::Purpose) -> String {
        self.management_urls(purpose)[0].clone()
    }
}
#[derive(Clone)]
pub(crate) struct ManagementEndpoint(String);

pub fn routers(
    app: Arc<HttpState>,
    enrollment_boundary: boundary::Envelope,
    management_boundary: boundary::Envelope,
) -> (
    Router<(), impl rss_mdm_http_contract::module::Declaration + use<>>,
    Router<(), impl rss_mdm_http_contract::module::Declaration + use<>>,
) {
    let (enrollment, management) = mount_native(
        Some(app),
        Some(format!("https://{}", management_boundary.host)),
    );
    (
        boundary::wrap(enrollment, enrollment_boundary),
        boundary::wrap(management, management_boundary),
    )
}
/// Same native declarations for production and offline contract export.
pub fn mount_native(
    app: Option<Arc<HttpState>>,
    management_origin: Option<String>,
) -> (
    Router<(), impl rss_mdm_http_contract::module::Declaration + use<>>,
    Router<(), impl rss_mdm_http_contract::module::Declaration + use<>>,
) {
    let enrollment = {
        rss_mdm_http_contract::route_module! { struct RoutersModule1 for [WindowsEnrollment] { renewal_discovery, external_post_policy, external_post_issue } }
        RoutersModule1 {
            renewal_discovery: certificate_enrollment::renewal_discovery_router(),
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
        }
        .assemble()
    };
    let management = {
        rss_mdm_http_contract::route_module! { struct RoutersModule101 for [WindowsManagement] { base, external_post_discover, external_post_policy, external_post_issue, external_post_manage, external_post_manage_2 } }
        RoutersModule101 {
            base: certificate_enrollment::router(),
            external_post_discover: rss_mdm_http_contract::module::Route::new(
                "/EnrollmentConfiguration",
                rss_mdm_http_contract::routing::external_post(
                    linked::discover,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_post_policy: rss_mdm_http_contract::module::Route::new(
                "/EnrollmentServer/LinkedPolicy.svc",
                rss_mdm_http_contract::routing::external_post(
                    linked::policy,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_post_issue: rss_mdm_http_contract::module::Route::new(
                "/EnrollmentServer/LinkedEnrollment.svc",
                rss_mdm_http_contract::routing::external_post(
                    linked::issue,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_post_manage: rss_mdm_http_contract::module::Route::new(
                "/ManagementServer/MDM.svc",
                rss_mdm_http_contract::routing::external_post(
                    management::manage,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            external_post_manage_2: rss_mdm_http_contract::module::Route::new(
                "/ManagementServer/Declared.svc",
                rss_mdm_http_contract::routing::external_post(
                    management::manage,
                    rss_mdm_http_contract::ExternalProtocol::WindowsMdm,
                    &contracts::PROTOCOL_WINDOWS_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
        }
        .assemble()
    };

    let windows = app.as_ref().and_then(|app| app.windows.as_ref());
    let discovery = discovery_routes(
        windows
            .map(|w| w.enrollment_origin.clone())
            .unwrap_or_default(),
        windows.map(|w| soap::DiscoverResponse {
            auth_policy: soap::AuthPolicy::OnPremise,
            enrollment_version: "4.0".into(),
            policy_url: format!("{}/EnrollmentServer/Policy.svc", w.enrollment_origin),
            enrollment_url: format!("{}/EnrollmentServer/Enrollment.svc", w.enrollment_origin),
        }),
    );
    rss_mdm_http_contract::route_module! { struct WindowsEnrollmentModule for [WindowsEnrollment] { enrollment, discovery } }
    let enrollment = WindowsEnrollmentModule {
        enrollment: enrollment.bind_with(app.as_ref(), Clone::clone),
        discovery,
    }
    .assemble()
    .layer(DefaultBodyLimit::max(512 * 1024));
    let management = management.bind_with(app.as_ref(), Clone::clone);
    let management = match management_origin {
        Some(origin) => management.layer(Extension(ManagementEndpoint(origin))),
        None => management,
    };
    (
        enrollment,
        management.layer(DefaultBodyLimit::max(512 * 1024)),
    )
}

fn decode(
    bytes: &[u8],
    headers: &HeaderMap,
    op: Operation,
    origin: Result<&str, Error>,
    path: &str,
) -> Result<soap::Message, Error> {
    decode_at(bytes, headers, op, origin?, path)
}
fn decode_at(
    bytes: &[u8],
    headers: &HeaderMap,
    op: Operation,
    origin: &str,
    path: &str,
) -> Result<soap::Message, Error> {
    if headers.get_all("content-type").iter().count() != 1
        || !headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|s| {
                s.split(';')
                    .next()
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/soap+xml"))
            })
    {
        return Err(Error::Malformed);
    }
    let message = soap::decode(bytes, op, &CodecLimits::default()).map_err(|_| Error::Malformed)?;
    if message.header.to.as_deref() != Some(format!("{origin}{path}").as_str()) {
        return Err(Error::Malformed);
    }
    Ok(message)
}
fn response(request: Option<&soap::Message>, body: Body, now: i64) -> Result<Response, Error> {
    let time = |n| {
        time::OffsetDateTime::from_unix_timestamp(n)
            .map_err(|_| Error::Unavailable(Failure::Clock))?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| Error::Unavailable(Failure::Clock))
    };
    let security = if matches!(body, Body::IssueResponse(_)) {
        Some(soap::Security {
            binary_token: None,
            signature: false,
            username: None,
            timestamp: Some(soap::Timestamp {
                id: "_0".into(),
                created: time(now)?,
                expires: time(now + 300)?,
            }),
        })
    } else {
        None
    };
    let message = soap::Message {
        header: soap::Header {
            message_id: None,
            relates_to: request
                .and_then(|r| r.header.message_id.clone())
                .or(Some("urn:uuid:invalid".into())),
            to: None,
            reply_to: false,
            security,
        },
        body,
    };
    let bytes = soap::encode(&message, &CodecLimits::default())
        .map_err(|_| Error::Unavailable(Failure::Protocol))?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/soap+xml; charset=utf-8",
        )],
        bytes,
    )
        .into_response())
}
pub fn fault(request: Option<&soap::Message>, error: Error) -> Response {
    let kind = match error {
        Error::Malformed => soap::FaultKind::MessageFormat,
        Error::CertificateRequest => soap::FaultKind::CertificateRequest,
        Error::Unauthorized => soap::FaultKind::Authentication,
        Error::Forbidden | Error::Conflict => soap::FaultKind::Authorization,
        _ => soap::FaultKind::EnrollmentServer,
    };
    let mut r = response(request, Body::Fault(kind), 0)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r.extensions_mut().insert(error);
    r
}
async fn discovery_probe() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_LENGTH, "0")],
        "",
    )
}
pub fn discovery_routes(
    origin: String,
    response: Option<soap::DiscoverResponse>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
 rss_mdm_http_contract::route_module! { struct DiscoveryRoutesModule1 for [WindowsEnrollment] { external_get_discovery_probe, external_post_discover } }
 DiscoveryRoutesModule1 { external_get_discovery_probe: rss_mdm_http_contract::module::Route::new("/EnrollmentServer/Discovery.svc", rss_mdm_http_contract::routing::external_get(
                discovery_probe,
                rss_mdm_http_contract::ExternalProtocol::WindowsMdm, &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action])),
external_post_discover: rss_mdm_http_contract::module::Route::new("/EnrollmentServer/Discovery.svc", rss_mdm_http_contract::routing::external_post(
                discover,
                rss_mdm_http_contract::ExternalProtocol::WindowsMdm, &contracts::PROTOCOL_WINDOWS_CHANNEL,
                &[RouteOperation::Action])) }.assemble()
}
        .with_state((origin, response))
}
async fn discover(
    State((origin, discovery)): State<(String, Option<soap::DiscoverResponse>)>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let Some(mut discovery) = discovery else {
        return fault(None, Error::Unsupported);
    };
    let message = match decode(
        &bytes,
        &headers,
        Operation::Discover,
        Ok(&origin),
        "/EnrollmentServer/Discovery.svc",
    ) {
        Ok(message) => message,
        Err(error) => return fault(None, error),
    };
    let Body::Discover(request) = &message.body else {
        return fault(Some(&message), Error::Malformed);
    };
    // MS-MDE2 DiscoveryRequest negotiates protocol support; the subsequent credential
    // selects and authorizes its tenant. No tenant's cached Entra configuration is a host default.
    // ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/36e33def-59ab-484f-b0bc-701496346925
    let password_request = request.email.0.split_once('@').is_some_and(|(id, domain)| {
        uuid::Uuid::parse_str(id).is_ok_and(|id| !id.is_nil())
            && origin
                .parse::<axum::http::Uri>()
                .ok()
                .and_then(|u| u.host().map(str::to_owned))
                .as_deref()
                == Some(domain)
    });
    discovery.auth_policy =
        if password_request && request.auth_policies.contains(&soap::AuthPolicy::OnPremise) {
            soap::AuthPolicy::OnPremise
        } else if request.auth_policies.contains(&soap::AuthPolicy::Federated) {
            soap::AuthPolicy::Federated
        } else if request.auth_policies.contains(&soap::AuthPolicy::OnPremise) {
            soap::AuthPolicy::OnPremise
        } else {
            return fault(Some(&message), Error::Unsupported);
        };
    response(Some(&message), Body::DiscoverResponse(discovery), 0)
        .unwrap_or_else(|error| fault(Some(&message), error))
}

async fn policy(
    Extension(control): Extension<rss_axum::RequestControl>,
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Response {
    enrollment(app, headers, audit, bytes, false, control.deadline()).await
}
async fn issue(
    Extension(control): Extension<rss_axum::RequestControl>,
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Response {
    enrollment(app, headers, audit, bytes, true, control.deadline()).await
}
async fn enrollment(
    app: Arc<HttpState>,
    headers: HeaderMap,
    audit: RequestAudit,
    bytes: Bytes,
    issuing: bool,
    cutoff: rss_request_context::Deadline,
) -> Response {
    let (op, path) = if issuing {
        (Operation::Issue, "/EnrollmentServer/Enrollment.svc")
    } else {
        (Operation::GetPolicies, "/EnrollmentServer/Policy.svc")
    };
    let message = match decode(
        &bytes,
        &headers,
        op,
        app.windows
            .as_ref()
            .map(|w| w.enrollment_origin.as_str())
            .ok_or(Error::Unsupported),
        path,
    ) {
        Ok(m) => m,
        Err(e) => return fault(None, e),
    };
    let result = async {
        validate_timestamp(
            message.header.security.as_ref(),
            app.clock
                .unix_seconds()
                .ok_or(Error::Unavailable(Failure::Clock))?,
        )?;
        if matches!(
            &message.body,
            Body::Issue(soap::Issue {
                request: soap::CertificateRequest::RenewalPkcs7(_),
                ..
            })
        ) {
            return Err(Error::Forbidden);
        }
        let security = message
            .header
            .security
            .as_ref()
            .ok_or(Error::Unauthorized)?;
        if let Some(token) = &security.binary_token {
            if security.signature {
                return Err(Error::Unsupported);
            }
            return entra::enrollment(&app, &message, &audit, issuing, &token.bytes.0, cutoff)
                .await;
        }
        let token = security.username.as_ref().ok_or(Error::Unauthorized)?;
        let id = app
            .windows
            .as_ref()
            .ok_or(Error::Unsupported)?
            .request_id(&token.username.0)?;
        let execution = app.request_binding(id).await?;
        let windows = app.windows(execution).await?;
        audit
            .bind_scope(execution)
            .map_err(|_| Error::Unauthorized)?;
        let password = Password::new(token.password.0.clone()).map_err(|_| Error::Unauthorized)?;
        if let Some(response) = agent_enrollment::try_enrollment(
            &app, &windows, execution, id, &password, &message, &audit, issuing,
        )
        .await?
        {
            return Ok(response);
        }
        let auth = crate::enrollment::store::enrollment_authorization(
            rss_mdm_install_support::StorageProfile::Mdm,
            &app.access.registration(),
            &execution.tenant().to_string(),
            id,
            &password,
        )
        .await?;
        if auth.expected_epoch != execution.epoch().get()
            || auth.source != rss_mdm_inventory::ReportSource::MdmWindows
        {
            return Err(Error::Unauthorized);
        }
        let credential = app.credentials.get(auth.credential_ref)?;

        let proof = app
            .identity
            .authenticate(
                execution,
                &app.access.authorization,
                credential,
                rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                    cutoff,
                    &rss_mdm_audit_integration::budget::RuntimeTimer,
                ),
            )
            .await?;
        if proof.principal_id() != auth.actor || proof.instance_id() != auth.instance {
            return Err(Error::Unauthorized);
        }
        auth.authorize(&proof)?;
        proof.bind_audit(&audit)?;
        audit.target_device(&auth.device);
        let now = app
            .clock
            .unix_seconds()
            .ok_or(Error::Unavailable(Failure::Clock))?;
        if let Some(t) = &security.timestamp {
            let parse = |v: &str| {
                time::OffsetDateTime::parse(v, &time::format_description::well_known::Rfc3339)
                    .map(|t| t.unix_timestamp())
                    .map_err(|_| Error::Malformed)
            };
            let (created, expires) = (parse(&t.created)?, parse(&t.expires)?);
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
            return response(
                Some(&message),
                Body::GetPoliciesResponse(soap::Policy {
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
        let Body::Issue(input) = &message.body else {
            return Err(Error::Malformed);
        };
        let soap::CertificateRequest::Pkcs10(csr) = &input.request else {
            return Err(Error::Unsupported);
        };
        for (key, value) in &input.additional_context.0 {
            // A self-service request owns a new server identity. The terminal DeviceID
            // is descriptive input; it cannot select or supersede another registration.
            if key == "DeviceID" && !auth.self_service && value != &auth.device.to_string() {
                return Err(Error::Forbidden);
            }
        }
        let enrollment_type = match input
            .additional_context
            .0
            .iter()
            .find(|(k, _)| k == "EnrollmentType")
            .map(|(_, v)| v.as_str())
        {
            Some("Full") => rss_mdm_windows_mdm::provisioning::EnrollmentType::Full,
            Some("Device") => rss_mdm_windows_mdm::provisioning::EnrollmentType::Device,
            _ => return Err(Error::Malformed),
        };
        audit.operation(
            auth.operation,
            "enrollment_issue",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let intent = crate::issuance::issuance_for_device(
            &app.audit_store,
            &windows,
            &auth,
            &proof,
            (&csr.0, enrollment_type),
            input
                .additional_context
                .0
                .iter()
                .find(|(k, _)| k == "DeviceID")
                .map(|(_, v)| v.as_str()),
            now,
        )
        .await?;
        let certificate = issuance::sign(&app, proof.binding(), &windows, &intent, now).await?;
        let provisioning =
            issuance::provision(&windows, &intent, &certificate, &auth, proof.tenant_id())?;
        let proof = app
            .identity
            .authenticate(
                execution,
                &app.access.authorization,
                app.credentials.get(auth.credential_ref)?,
                rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                    cutoff,
                    &rss_mdm_audit_integration::budget::RuntimeTimer,
                ),
            )
            .await?;
        auth.authorize(&proof)?;
        crate::issuance::complete_issuance(
            &app.audit_store,
            &windows,
            &auth,
            &proof,
            &intent,
            &certificate,
            &audit,
            app.clock
                .unix_seconds()
                .ok_or(Error::Unavailable(Failure::Clock))?,
            &app.mount,
        )
        .await?;
        response(
            Some(&message),
            Body::IssueResponse(soap::IssueResponse {
                context: input.context.clone(),
                provisioning: Secret(provisioning),
                request_id: Some(soap::NillableText::Value(Secret(auth.id.to_string()))),
                disposition: None,
            }),
            now,
        )
    }
    .await;
    result.unwrap_or_else(|e| fault(Some(&message), e))
}

pub struct HttpState {
    pub pki: Arc<rss_mdm_pki_service::registry::Registry>,
    pub providers: Arc<rss_mdm_pki_service::providers::Providers>,
    pub storage: rss_transactional_messaging::fence::StorageIdentity,
    pub expected_epoch: rss_transactional_messaging::fence::Epoch,
    pub query_cursor: rss_mdm_query::cursor::CursorCodec,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub mount: crate::device::ChannelMount,
    pub audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    pub access: std::sync::Arc<crate::Store>,
    pub clock: std::sync::Arc<dyn rss_mdm_inventory_service::clock::Clock>,
    pub delivery: Arc<management::exchange::Delivery>,
    pub enrollment_authority:
        Arc<dyn rss_mdm_registration_service::enrollment::native::AgentPolicyAuthority>,
    pub departure: Arc<dyn crate::participants::Departure>,
    pub credentials: std::sync::Arc<crate::enrollment::credentials::Credentials>,
    pub devices: std::sync::Arc<crate::device::DeviceService>,
    pub identity: std::sync::Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub buffered_bytes: std::sync::Arc<tokio::sync::Semaphore>,
    pub windows: Option<Arc<runtime_materials::Runtime>>,
}
impl HttpState {
    pub async fn windows(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Arc<Windows>, Error> {
        self.windows
            .as_ref()
            .ok_or(Error::Unsupported)?
            .load(self, execution)
            .await
    }
}

use rss_mdm_audit_integration::RequestAudit;

#[cfg(test)]
#[path = "../tests/unit.rs"]
mod tests;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub mod boundary;

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

mod template_collection;

fn validate_timestamp(security: Option<&soap::Security>, now: i64) -> Result<(), Error> {
    if let Some(t) = security.and_then(|s| s.timestamp.as_ref()) {
        let parse = |v: &str| {
            time::OffsetDateTime::parse(v, &time::format_description::well_known::Rfc3339)
                .map(|t| t.unix_timestamp())
                .map_err(|_| Error::Malformed)
        };
        let (created, expires) = (parse(&t.created)?, parse(&t.expires)?);
        if created > now + 30
            || created < now - 300
            || expires <= now
            || expires <= created
            || expires - created > 300
        {
            return Err(Error::Unauthorized);
        }
    }
    Ok(())
}

/// Participate in retirement without committing or deleting historical receipts.
pub async fn retire_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registration: &rss_mdm_agent_wire::DeviceId,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_windows.push_channels SET lease_id = NULL, lease_until = NULL WHERE tenant_id = CAST($1 AS uuid) AND device = $2")
        .bind(tenant).bind(registration.into_uuid()).execute(&mut *c).await.map_err(database::db)?;
    sqlx::query("UPDATE mdm_access.management_sessions SET state = 'superseded' WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND state IN ('challenge', 'collecting')")
        .bind(tenant).bind(registration.into_uuid()).execute(c).await.map_err(database::db)?;
    Ok(())
}

pub const ENTRA_SQL: &str = include_str!("../schema/entra.sql");

/// Durable browser TOU flows and explicit legacy policy upgrade.
pub const ENTRA_WEB_SQL: &str = include_str!("../schema/entra-web.sql");

/// This owner's exact privileges in the shared host transaction role.
pub const UPDATE_COLUMNS: &str = include_str!("update-columns.sql");

/// This owner's exact privileges in the shared host transaction role.
pub const ALLOWED_TABLES: &str = include_str!("allowed-tables.sql");

/// Structural contract for this owner's durable delivery facts; App verifies the complete role.
pub async fn verify_delivery(c: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let allowed: bool = sqlx::query_scalar(include_str!("delivery-admission.sql"))
        .fetch_one(c)
        .await?;
    if !allowed {
        return Err(sqlx::Error::Protocol(
            "channel delivery storage rejected".into(),
        ));
    }
    Ok(())
}

pub mod command_binding;
pub const NATIVE_COMMANDS_SQL: &str = include_str!("../schema/native-commands.sql");

#[cfg(test)]
#[path = "../tests/collection_plan.rs"]
mod collection_plan_tests;

impl HttpState {
    pub fn execution(
        &self,
        tenant: rss_request_context::TenantId,
    ) -> rss_transactional_messaging::fence::ExecutionBinding {
        rss_transactional_messaging::fence::ExecutionBinding::new(
            self.storage,
            tenant,
            self.expected_epoch,
        )
    }
    pub async fn certificate_binding(
        &self,
        peer: &rss_mdm_certificate::ClientCertificateEvidence,
    ) -> Result<rss_transactional_messaging::fence::ExecutionBinding, Error> {
        use sha2::Digest;
        let certificate = peer.chain().first().ok_or(Error::Unauthorized)?;
        let fingerprint: [u8; 32] = sha2::Sha256::digest(certificate.as_ref()).into();
        let tenant = self
            .access
            .locate_certificate(fingerprint)
            .await?
            .ok_or(Error::Unauthorized)?;
        Ok(self.execution(tenant))
    }
    pub async fn request_binding(
        &self,
        request: uuid::Uuid,
    ) -> Result<rss_transactional_messaging::fence::ExecutionBinding, Error> {
        let (tenant, epoch) = self
            .access
            .registration
            .locate_request(request)
            .await?
            .ok_or(Error::Unauthorized)?;
        Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
            self.storage,
            tenant,
            epoch,
        ))
    }
}
