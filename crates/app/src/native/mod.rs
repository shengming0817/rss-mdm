//! Native transports share ingress limits and TLS ownership, never protocol state.
pub(crate) mod admission;
pub(crate) mod tls;
use axum::Router;
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsEndpoint {
    pub listen: SocketAddr,
    pub origin: String,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}
pub(crate) struct TlsRouter {
    pub(crate) admission: Arc<admission::Admission>,
    pub listen: SocketAddr,
    pub tls: Arc<tokio_rustls::rustls::ServerConfig>,
    pub router: Router,
}
pub(crate) struct Routers {
    pub apple: Option<Arc<crate::apple::Apple>>,
    pub browser: Router,
    pub listeners: Vec<(&'static str, TlsRouter)>,
}
