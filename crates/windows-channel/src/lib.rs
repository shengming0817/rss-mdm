//! Windows enrollment and management protocol boundary.
mod database;
pub mod enrollment_store;
pub mod issuance;
pub mod management;
mod operations;
mod protection;
pub mod retention;
pub use database::Store;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure};
mod error;
pub use error::Error;
use rss_mdm_authorization_service as authorization;
use rss_mdm_registration_service::{device, enrollment};
mod agent_collection;
mod collection;
mod large_object;
mod notifications;
mod transcript;
use axum::{
    Extension, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use enrollment::Password;
use rss_mdm_certificate::windows as certificate;
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    soap::{self, Body, Operation},
};
use std::sync::Arc;
use uuid::Uuid;

pub struct Windows {
    pub agent_identity: Option<rss_mdm_execution_service::agent_install::Identity>,
    pub enrollment_origin: String,
    pub management_origin: String,
    pub provider_id: String,
    pub ca: certificate::WindowsEnrollmentAuthority,
    protection: protection::Protection,
    configuration: String,
}
impl Windows {
    pub fn new(
        enrollment_origin: String,
        management_origin: String,
        provider_id: String,
        ca: certificate::WindowsEnrollmentAuthority,
        protocol_key: &[u8],
    ) -> Result<Self, Error> {
        let protection = protection::Protection::from_bytes(protocol_key)?;
        let configuration = enrollment::digest(&(
            "mdm.windows.profile.v1",
            &enrollment_origin,
            &management_origin,
            &provider_id,
            ca.der(),
            &protection.id,
        ));
        Ok(Self {
            agent_identity: None,
            enrollment_origin,
            management_origin,
            provider_id,
            ca,
            protection,
            configuration,
        })
    }
    pub fn management_url(&self) -> String {
        format!("{}/ManagementServer/MDM.svc", self.management_origin)
    }
}
pub fn routers(
    app: Arc<HttpState>,
    enrollment_boundary: boundary::Envelope,
    management_boundary: boundary::Envelope,
) -> (Router, Router) {
    let enrollment = Router::new()
        .route("/EnrollmentServer/Discovery.svc", post(discover))
        .route("/EnrollmentServer/Policy.svc", post(policy))
        .route("/EnrollmentServer/Enrollment.svc", post(issue));
    let management = Router::new()
        .route("/ManagementServer/MDM.svc", post(management::manage))
        .route(
            "/api/agent/v5/managed-registrations",
            post(management::register_agent),
        );
    (
        boundary::wrap(
            enrollment
                .with_state(app.clone())
                .layer(DefaultBodyLimit::max(512 * 1024)),
            enrollment_boundary,
        ),
        boundary::wrap(
            management
                .with_state(app)
                .layer(DefaultBodyLimit::max(512 * 1024)),
            management_boundary,
        ),
    )
}
fn decode(
    bytes: &[u8],
    headers: &HeaderMap,
    op: Operation,
    app: &HttpState,
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
    if message.header.to.as_deref()
        != Some(format!("{}{path}", app.windows()?.enrollment_origin).as_str())
    {
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
async fn discover(State(app): State<Arc<HttpState>>, headers: HeaderMap, bytes: Bytes) -> Response {
    let windows = match app.windows() {
        Ok(windows) => windows,
        Err(e) => return fault(None, e),
    };
    let message = match decode(
        &bytes,
        &headers,
        Operation::Discover,
        &app,
        "/EnrollmentServer/Discovery.svc",
    ) {
        Ok(m) => m,
        Err(e) => return fault(None, e),
    };
    response(
        Some(&message),
        Body::DiscoverResponse(soap::DiscoverResponse {
            enrollment_version: "4.0".into(),
            policy_url: format!("{}/EnrollmentServer/Policy.svc", windows.enrollment_origin),
            enrollment_url: format!(
                "{}/EnrollmentServer/Enrollment.svc",
                windows.enrollment_origin
            ),
        }),
        0,
    )
    .unwrap_or_else(|e| fault(Some(&message), e))
}
async fn policy(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Response {
    enrollment(app, headers, audit, bytes, false).await
}
async fn issue(
    State(app): State<Arc<HttpState>>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    bytes: Bytes,
) -> Response {
    enrollment(app, headers, audit, bytes, true).await
}
async fn enrollment(
    app: Arc<HttpState>,
    headers: HeaderMap,
    audit: RequestAudit,
    bytes: Bytes,
    issuing: bool,
) -> Response {
    let (op, path) = if issuing {
        (Operation::Issue, "/EnrollmentServer/Enrollment.svc")
    } else {
        (Operation::GetPolicies, "/EnrollmentServer/Policy.svc")
    };
    let message = match decode(&bytes, &headers, op, &app, path) {
        Ok(m) => m,
        Err(e) => return fault(None, e),
    };
    let result = async {
        let security = message
            .header
            .security
            .as_ref()
            .ok_or(Error::Unauthorized)?;
        let token = security.username.as_ref().ok_or(Error::Unauthorized)?;
        let id = Uuid::parse_str(&token.username.0).map_err(|_| Error::Unauthorized)?;
        let password = Password::new(token.password.0.clone()).map_err(|_| Error::Unauthorized)?;
        let auth = crate::enrollment::store::enrollment_authorization(
            &app.access.registration(),
            &app.identity.tenant().to_string(),
            id,
            &password,
        )
        .await?;
        if auth.source != rss_mdm_inventory::ReportSource::MdmWindows {
            return Err(Error::Unauthorized);
        }
        let credential = app.credentials.get(auth.credential_ref)?;
        let _global = app
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable(Failure::Capacity))?;
        let proof = app
            .identity
            .authenticate(&app.access.authorization, credential)
            .await?;
        if proof.principal_id() != auth.actor || proof.instance_id() != auth.instance {
            return Err(Error::Unauthorized);
        }
        let _permission = proof.enrollment(&auth.device)?;
        proof.bind_audit(&audit)?;
        audit.target(&auth.device);
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
                    validity_seconds: 90 * 86400,
                    renewal_seconds: 7 * 86400,
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
        for (key, value) in &input.additional_context.0 {
            if key == "DeviceID" && value != &auth.device {
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
        audit.operation(auth.operation, "enrollment_issue");
        let intent = crate::issuance::issuance_intent(
            &app.access,
            app.windows()?,
            &auth,
            &proof,
            (&input.csr.0, enrollment_type),
            now,
        )
        .await?;
        let certificate =
            match crate::issuance::issued_certificate(&app.access, proof.tenant_id(), auth.id)
                .await?
            {
                Some(certificate) => certificate,
                None => app.windows()?.ca.sign(&app.windows()?.ca.restore_intent(
                    &intent.tbs,
                    &certificate::Csr::verify(&intent.csr)?,
                    intent.registration,
                )?)?,
            };
        let provisioning = issuance::provision(
            app.windows()?,
            &intent,
            &certificate,
            &auth,
            proof.tenant_id(),
        )?;
        let proof = app
            .identity
            .authenticate(
                &app.access.authorization,
                app.credentials.get(auth.credential_ref)?,
            )
            .await?;
        let _permission = proof.enrollment(&auth.device)?;
        crate::issuance::complete_issuance(
            &app.audit_store,
            app.windows()?,
            &auth,
            &proof,
            &intent,
            &certificate,
            &audit,
            app.clock
                .unix_seconds()
                .ok_or(Error::Unavailable(Failure::Clock))?,
            &app.mount,
            app.devices.retirement(),
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
    pub mount: crate::device::ChannelMount,
    pub audit_store: std::sync::Arc<rss_mdm_audit_integration::AuditStore>,
    pub access: std::sync::Arc<crate::Store>,
    pub clock: std::sync::Arc<dyn rss_mdm_inventory_service::clock::Clock>,
    pub execution: std::sync::Arc<rss_mdm_execution_service::ExecutionService>,
    pub credentials: std::sync::Arc<crate::enrollment::credentials::Credentials>,
    pub devices: std::sync::Arc<crate::device::DeviceService>,
    pub identity: std::sync::Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub requests: std::sync::Arc<tokio::sync::Semaphore>,
    pub windows: Option<std::sync::Arc<crate::Windows>>,
}
impl HttpState {
    pub fn windows(&self) -> std::result::Result<&Arc<crate::Windows>, crate::Error> {
        self.windows.as_ref().ok_or(crate::Error::Unsupported)
    }
}

use rss_mdm_audit_integration::RequestAudit;

#[cfg(test)]
#[path = "../tests/unit.rs"]
mod tests;

#[cfg(feature = "integration")]
pub mod test_support {
    pub use crate::collection::{accept, create};
    pub use crate::protection::{Secrets, digest};
}
#[cfg(feature = "integration")]
impl Windows {
    pub fn open_secrets_fixture(
        &self,
        tenant: &str,
        request: Uuid,
        sealed: &[u8],
    ) -> Result<test_support::Secrets, Error> {
        self.protection.open(tenant, request, sealed)
    }
}

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub mod boundary;

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

mod template_collection;
