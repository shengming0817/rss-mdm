//! Product Windows enrollment/management assembly. TLS and authority stay outside the codec.
mod admission;
pub(crate) mod certificate;
mod issuance;
mod management;
mod protection;
pub(crate) mod retention;
#[cfg(test)]
mod retention_tests;
#[cfg(test)]
mod tests;
pub(crate) mod tls;
use crate::{
    ConfigIssue, Error, Failure,
    api::{App, Envelope, authenticate, envelope},
    audit::Audit,
    enrollment::Password,
};
use axum::{
    Extension, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use rss_mdm_windows_mdm::{
    CodecLimits, Secret,
    soap::{self, Body, Operation},
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsEndpoint {
    pub listen: SocketAddr,
    pub origin: String,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsConfig {
    pub enrollment: TlsEndpoint,
    pub management: TlsEndpoint,
    pub ca_certificate_file: PathBuf,
    pub ca_private_key_file: PathBuf,
    pub protocol_key_file: PathBuf,
    pub provider_id: String,
}
impl WindowsConfig {
    pub(crate) fn validate(&self, browser: SocketAddr) -> Result<(), Error> {
        if self.enrollment.listen == self.management.listen
            || self.enrollment.listen == browser
            || self.management.listen == browser
            || self.enrollment.origin == self.management.origin
            || self.provider_id.is_empty()
            || self.provider_id.len() > 64
            || !self
                .provider_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(Error::Configuration(ConfigIssue::WindowsListeners));
        }
        for endpoint in [&self.enrollment, &self.management] {
            let u = crate::config::https_url(&endpoint.origin)
                .map_err(|_| Error::Configuration(ConfigIssue::WindowsListeners))?;
            if u.origin().ascii_serialization() != endpoint.origin || endpoint.listen.port() == 0 {
                return Err(Error::Configuration(ConfigIssue::WindowsListeners));
            }
        }
        Ok(())
    }
}
pub(crate) struct Windows {
    config: WindowsConfig,
    ca: certificate::Ca,
    protection: protection::Protection,
    configuration: String,
    pub(crate) enrollment_tls: Arc<tokio_rustls::rustls::ServerConfig>,
    pub(crate) management_tls: Arc<tokio_rustls::rustls::ServerConfig>,
}
impl Windows {
    pub(crate) fn load(config: WindowsConfig, now: i64) -> Result<Self, Error> {
        let ca = certificate::Ca::load(
            &config.ca_certificate_file,
            &config.ca_private_key_file,
            now,
        )
        .map_err(|_| Error::Configuration(ConfigIssue::EnrollmentCa))?;
        let protection = protection::Protection::load(&config.protocol_key_file)
            .map_err(|_| Error::Configuration(ConfigIssue::ProtocolKey))?;
        let configuration = crate::enrollment::digest(&(
            "mdm.windows.profile.v1",
            &config.enrollment.origin,
            &config.management.origin,
            &config.provider_id,
            &ca.der,
            &protection.id,
        ));
        let enrollment_tls = tls::configuration(&config.enrollment, None)?;
        let management_tls = tls::configuration(&config.management, Some(ca.verifier.clone()))?;
        Ok(Self {
            config,
            ca,
            protection,
            configuration,
            enrollment_tls,
            management_tls,
        })
    }
    fn management_url(&self) -> String {
        format!("{}/ManagementServer/MDM.svc", self.config.management.origin)
    }
}
pub(crate) struct TlsRouter {
    admission: Arc<admission::Admission>,
    pub listen: SocketAddr,
    pub tls: Arc<tokio_rustls::rustls::ServerConfig>,
    pub router: Router,
}
pub(crate) struct Routers {
    pub browser: Router,
    pub enrollment: TlsRouter,
    pub management: TlsRouter,
}
pub(crate) fn routers(
    app: Arc<App>,
    clock: Arc<dyn rss_observation::Clock>,
) -> (TlsRouter, TlsRouter) {
    let wrap = |router: Router<Arc<App>>, origin: &str| {
        router
            .with_state(app.clone())
            .layer(DefaultBodyLimit::max(512 * 1024))
            .layer(middleware::from_fn_with_state(
                Envelope {
                    host: origin.trim_start_matches("https://").into(),
                    clock: clock.clone(),
                    access: app.access.clone(),
                    tenant: app.identity.tenant.to_string(),
                },
                envelope,
            ))
            .layer(middleware::from_fn(admission::admit))
    };
    let enrollment = wrap(
        Router::new()
            .route("/EnrollmentServer/Discovery.svc", post(discover))
            .route("/EnrollmentServer/Policy.svc", post(policy))
            .route("/EnrollmentServer/Enrollment.svc", post(issue)),
        &app.windows.config.enrollment.origin,
    );
    let management = wrap(
        Router::new().route("/ManagementServer/MDM.svc", post(management::manage)),
        &app.windows.config.management.origin,
    );
    (
        TlsRouter {
            admission: admission::Admission::new(
                clock.clone(),
                app.requests.clone(),
                "mdm-enrollment-tls",
            ),
            listen: app.windows.config.enrollment.listen,
            tls: app.windows.enrollment_tls.clone(),
            router: enrollment,
        },
        TlsRouter {
            admission: admission::Admission::new(clock, app.requests.clone(), "mdm-management-tls"),
            listen: app.windows.config.management.listen,
            tls: app.windows.management_tls.clone(),
            router: management,
        },
    )
}
fn decode(
    bytes: &[u8],
    headers: &HeaderMap,
    op: Operation,
    app: &App,
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
        != Some(format!("{}{path}", app.windows.config.enrollment.origin).as_str())
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
pub(crate) fn fault(request: Option<&soap::Message>, error: Error) -> Response {
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
async fn discover(State(app): State<Arc<App>>, headers: HeaderMap, bytes: Bytes) -> Response {
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
            policy_url: format!(
                "{}/EnrollmentServer/Policy.svc",
                app.windows.config.enrollment.origin
            ),
            enrollment_url: format!(
                "{}/EnrollmentServer/Enrollment.svc",
                app.windows.config.enrollment.origin
            ),
        }),
        0,
    )
    .unwrap_or_else(|e| fault(Some(&message), e))
}
async fn policy(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(audit): Extension<Audit>,
    bytes: Bytes,
) -> Response {
    enrollment(app, headers, audit, bytes, false).await
}
async fn issue(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Extension(audit): Extension<Audit>,
    bytes: Bytes,
) -> Response {
    enrollment(app, headers, audit, bytes, true).await
}
async fn enrollment(
    app: Arc<App>,
    headers: HeaderMap,
    audit: Audit,
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
        let auth = app
            .access
            .enrollment_authorization(&app.identity.tenant.to_string(), id, &password)
            .await?;
        let credential = app.credentials.get(auth.credential_ref)?;
        let _global = app
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable(Failure::Capacity))?;
        let proof = authenticate(&app, credential).await?;
        if proof.principal_id() != auth.actor || proof.instance_id() != auth.instance {
            return Err(Error::Unauthorized);
        }
        let _permission = proof.enrollment(&auth.device)?;
        audit.identify(&proof);
        audit.target(&auth.device);
        let now = app.clock.unix_seconds()?;
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
        let intent = app
            .access
            .issuance_intent(
                &app.windows,
                &auth,
                &proof,
                (&input.csr.0, enrollment_type),
                now,
            )
            .await?;
        let certificate = match app
            .access
            .issued_certificate(proof.tenant_id(), auth.id)
            .await?
        {
            Some(certificate) => certificate,
            None => app.windows.ca.sign(&intent.tbs)?,
        };
        let provisioning = issuance::provision(
            &app.windows,
            &intent,
            &certificate,
            &auth,
            proof.tenant_id(),
        )?;
        let proof = authenticate(&app, app.credentials.get(auth.credential_ref)?).await?;
        let _permission = proof.enrollment(&auth.device)?;
        app.access
            .complete_issuance(
                &app.windows,
                &auth,
                &proof,
                &intent,
                &certificate,
                &audit,
                app.clock.unix_seconds()?,
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
