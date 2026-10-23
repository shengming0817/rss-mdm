//! One internal HTTP ingress. Only the configured gateway can attest a TLS peer and source.
//! ref: nginx ngx_http_ssl_module.c ($ssl_client_escaped_cert); axum Router::oneshot.
use super::{ChannelKind, ChannelRouter};
use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rss_axum::{AcceptedConnectionInfo, ConnectionTransport, EstablishedTransport};
use rss_mdm_certificate::GatewayConnection;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::net::TcpStream;
use tower::ServiceExt;

pub(crate) struct Transport {
    pub gateway: IpAddr,
}
impl ConnectionTransport for Transport {
    type Io = TcpStream;
    type Metadata = GatewayConnection;
    type Guard = ();
    type Error = std::io::Error;
    async fn prepare(
        &self,
        stream: TcpStream,
        _peer: SocketAddr,
    ) -> Result<EstablishedTransport<Self::Io, Self::Metadata, Self::Guard>, Self::Error> {
        let gateway = GatewayConnection::from_stream(&stream, self.gateway).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "untrusted gateway")
        })?;
        Ok(EstablishedTransport::new(stream, gateway, ()))
    }
}
#[derive(Clone)]
struct Dispatch {
    browser: Router,
    routes: Arc<Vec<(ChannelKind, ChannelRouter)>>,
    product_origin: String,
    agent: Option<Arc<rss_mdm_registration_service::agent::Service>>,
}
pub(crate) fn router(
    browser: Router,
    routes: Vec<(ChannelKind, ChannelRouter)>,
    product_origin: String,
    agent: Option<Arc<rss_mdm_registration_service::agent::Service>>,
) -> Router {
    let routes = routes
        .into_iter()
        .map(|(kind, mut route)| {
            if kind == ChannelKind::Agent {
                route.router = route
                    .router
                    .layer(axum::middleware::from_fn(super::admission::admit_agent));
            }
            (kind, route)
        })
        .collect();
    Router::new().fallback(dispatch).with_state(Dispatch {
        browser,
        routes: Arc::new(routes),
        product_origin,
        agent,
    })
}
fn single<'a>(request: &'a Request, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = request.headers().get_all(name).iter();
    let value = values
        .next()
        .map(|v| v.to_str().map_err(|_| ()))
        .transpose()?;
    if values.next().is_some() {
        return Err(());
    }
    Ok(value)
}
fn kind(path: &str) -> Option<ChannelKind> {
    if path.starts_with("/api/v1/agent/") {
        Some(ChannelKind::Agent)
    } else if path.starts_with("/EnrollmentServer/") || path == "/EnrollmentConfiguration" {
        Some(ChannelKind::WindowsEnrollment)
    } else if path.starts_with("/ManagementServer/") {
        Some(ChannelKind::WindowsManagement)
    } else if matches!(path, "/checkin" | "/mdm") || path.starts_with("/native/apple/ddm/") {
        Some(ChannelKind::AppleManagement)
    } else {
        None
    }
}
fn attest(request: &mut Request) -> Result<(String, IpAddr), ()> {
    let Some(connection) = request
        .extensions()
        .get::<AcceptedConnectionInfo<GatewayConnection>>()
        .map(|c| c.metadata().clone())
    else {
        return Err(());
    };
    let origin = match single(request, "x-rss-public-origin") {
        Ok(Some(v)) => v.to_owned(),
        _ => return Err(()),
    };
    if rss_mdm_agent_wire::connections::validate_origin(&origin).is_err() {
        return Err(());
    }
    if single(request, "host") != Ok(origin.strip_prefix("https://")) {
        return Err(());
    }
    let source = match single(request, "x-forwarded-for")
        .ok()
        .flatten()
        .and_then(|v| v.parse::<IpAddr>().ok())
    {
        Some(v) if !v.is_unspecified() && !v.is_multicast() => v,
        _ => return Err(()),
    };
    let certificate = match single(request, "x-rss-client-cert") {
        Ok(Some(v)) if !v.is_empty() => match connection.client_certificate(v) {
            Ok(v) => Some(v),
            Err(_) => return Err(()),
        },
        Ok(_) => None,
        Err(_) => return Err(()),
    };
    let names = request
        .headers()
        .keys()
        .filter(|name| {
            name.as_str() == "forwarded"
                || name.as_str().starts_with("x-forwarded-")
                || matches!(name.as_str(), "x-rss-public-origin" | "x-rss-client-cert")
                || name.as_str().starts_with("x-ssl-")
                || matches!(
                    name.as_str(),
                    "x-real-ip" | "x-client-cert" | "x-device-id" | "x-tenant-id"
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in names {
        request.headers_mut().remove(name);
    }
    request
        .extensions_mut()
        .insert(connection.request_origin(origin.clone()));
    request
        .extensions_mut()
        .insert(rss_identity_http_axum::ClientAddress(source));
    if let Some(certificate) = certificate {
        request.extensions_mut().insert(certificate);
    }
    Ok((origin, source))
}
async fn dispatch(State(state): State<Dispatch>, mut request: Request) -> Response {
    let rejected = || {
        crate::http_host::secure_response(
            StatusCode::FORBIDDEN.into_response(),
            uuid::Uuid::new_v4(),
        )
    };
    let (origin, source) = match attest(&mut request) {
        Ok(value) => value,
        Err(()) => return rejected(),
    };
    if matches!(request.uri().path(), "/livez" | "/readyz") {
        // The gateway attests the configured TLS virtual host even while a device channel is waiting for material.
        let host = state
            .product_origin
            .strip_prefix("https://")
            .expect("validated origin");
        request.headers_mut().insert(
            "host",
            axum::http::HeaderValue::from_str(host).expect("canonical origin"),
        );
        return state
            .browser
            .oneshot(request)
            .await
            .unwrap_or_else(|never| match never {});
    }
    // Anonymous package delivery has one public contract, also usable from the console origin.
    let package_path = request
        .uri()
        .path()
        .strip_prefix("/api/v1/agent/enroll/packages")
        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'));
    if origin == state.product_origin && package_path {
        if !matches!(
            *request.method(),
            axum::http::Method::GET | axum::http::Method::HEAD
        ) {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        request.headers_mut().remove("cookie");
        request.headers_mut().remove("authorization");
        return state
            .browser
            .oneshot(request)
            .await
            .unwrap_or_else(|never| match never {});
    }
    let selected = kind(request.uri().path());
    let router = if let Some(selected) = selected {
        let Some((_, route)) = state.routes.iter().find(|(k, r)| {
            *k == selected && (*k == ChannelKind::Agent || r.origins.contains(&origin))
        }) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if selected == ChannelKind::Agent {
            let Some(agent) = &state.agent else {
                return rejected();
            };
            let allowed = match agent.connection_configuration().await {
                Ok(value) => value.configuration.origins.contains(&origin),
                Err(error)
                    if error.code == rss_mdm_agent_wire::enroll::ErrorCode::OperationConflict =>
                {
                    route.origins.contains(&origin)
                }
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            if !allowed {
                return rejected();
            }
        }
        let Some(gate) = route.admission.gate(source) else {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        };
        request.extensions_mut().insert(gate);
        route.router.clone()
    } else {
        if origin != state.product_origin {
            return rejected();
        }
        state.browser.clone()
    };
    router
        .oneshot(request)
        .await
        .unwrap_or_else(|never| match never {})
}
