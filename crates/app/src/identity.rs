//! Product assembly of the four public Identity components. The database is the authority.
use crate::{
    ConfigIssue, Error, Failure,
    access::Policy,
    config::{self, Config},
};
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_identity_core::{
    InstanceId,
    account::PasswordKdf,
    session::{SessionPolicy, SessionSecret},
};
use rss_identity_postgres::{AuthenticatedSession, Authority, AuthorityConfig, AuthorityError};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::{DeliveryBudget, OperationDeadline},
};
use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

pub(crate) fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(10))
}
fn invalid() -> Error {
    Error::Configuration(ConfigIssue::IdentityConfiguration)
}
pub(crate) fn failure(error: AuthorityError) -> Error {
    match error {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
        AuthorityError::CommitUnknown(_) | AuthorityError::RollbackFailed(_) => {
            Error::CommitUnknown
        }
        _ => Error::Unavailable(Failure::IdentityStorage),
    }
}
/// A single private projection, created only from a request's authoritative component result.
pub(crate) struct Principal {
    session: AuthenticatedSession,
    instance: String,
    tenant: String,
    principal: String,
}
impl Principal {
    pub(super) fn new(session: AuthenticatedSession) -> Result<Self, Error> {
        session.assurance().map_err(failure)?;
        Ok(Self {
            instance: session.instance().to_string(),
            tenant: session.account().tenant.to_string(),
            principal: session.account().principal.as_uuid().to_string(),
            session,
        })
    }
    pub(crate) fn check_live(&self) -> Result<(), Error> {
        self.session.assurance().map(|_| ()).map_err(failure)
    }
    pub(crate) fn instance_id(&self) -> &str {
        &self.instance
    }
    pub(crate) fn tenant_id(&self) -> &str {
        &self.tenant
    }
    pub(crate) fn principal_id(&self) -> &str {
        &self.principal
    }
}
pub(crate) struct Identity {
    pub(crate) authority: Authority,
    pub(crate) tenant: TenantId,
    routes: Router,
}
impl Identity {
    pub(crate) async fn connect(
        config: &Config,
        policy: Arc<Policy>,
        acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
    ) -> Result<Self, Error> {
        Self::connect_using(config, policy, acquire, OidcConfig::federation).await
    }
    async fn connect_using(
        config: &Config,
        policy: Arc<Policy>,
        mut acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
        federation: impl FnOnce(
            &OidcConfig,
            Authority,
            &str,
            InstanceId,
        ) -> Result<rss_identity_postgres::Federation, Error>,
    ) -> Result<Self, Error> {
        let tenant = TenantId::parse(&config.identity.tenant_id).map_err(|_| invalid())?;
        let instance = InstanceId::parse(&config.identity.instance_id).map_err(|_| invalid())?;
        let runtime = open_runtime(
            &config.identity.database,
            &config.management.target,
            &config.management.lineage,
            config.management.epoch,
            tenant,
        )
        .await?;
        acquire(rss_runtime::DynManagedResource::new_box(RuntimeResource(
            runtime.clone(),
        )));
        let kdf = Arc::new(PasswordKdf::new());
        acquire(rss_runtime::DynManagedResource::new_box(KdfResource(
            kdf.clone(),
        )));
        let authority = Authority::connect_runtime(
            runtime,
            kdf,
            authority_config(instance, tenant)?,
            policy,
            deadline(),
        )
        .await
        .map_err(failure)?;
        let http = rss_identity_http_axum::HttpConfig::new(
            &config.product_origin,
            Duration::from_secs(10),
        )
        .map_err(|_| invalid())?;
        let mut routes =
            rss_identity_http_axum::router(authority.clone(), http.clone()).map_err(failure)?;
        if let Some(oidc) = &config.identity.oidc {
            let federation = federation(oidc, authority.clone(), &config.product_origin, instance)?;
            routes = routes.merge(
                rss_identity_http_axum::federated_router(federation, http).map_err(failure)?,
            );
        }
        Ok(Self {
            authority,
            tenant,
            routes,
        })
    }
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn for_oidc_fixture(
        config: &Config,
        policy: Arc<Policy>,
    ) -> Result<Self, Error> {
        Self::connect_using(
            config,
            policy,
            |_| {},
            |config, authority, origin, instance| {
                let oidc = rss_identity_oidc::HttpOidc::for_loopback_test(config.profiles()?)
                    .map_err(|_| invalid())?;
                config.federation_using(authority, origin, instance, Arc::new(oidc))
            },
        )
        .await
    }
    pub(crate) fn routes(&self) -> Router {
        self.routes.clone()
    }
    pub(crate) async fn authenticate(
        &self,
        secret: SessionSecret,
        active: bool,
    ) -> Result<Principal, Error> {
        let session = if active {
            self.authority
                .authenticate_session(self.tenant, secret, deadline())
                .await
        } else {
            self.authority
                .inspect_session(self.tenant, secret, deadline())
                .await
        }
        .map_err(failure)?;
        Principal::new(session)
    }
}
pub(crate) fn authority_config(
    instance: InstanceId,
    tenant: TenantId,
) -> Result<AuthorityConfig, Error> {
    AuthorityConfig::new(
        instance,
        vec![tenant],
        SessionPolicy::new(900, 14400).map_err(|_| invalid())?,
        DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .map_err(|_| invalid())?,
    )
    .map_err(failure)
}
pub(crate) async fn open_runtime(
    database: &config::Database,
    target: &[u8; 16],
    lineage: &[u8; 16],
    epoch: i64,
    tenant: TenantId,
) -> Result<Arc<PgRuntime>, Error> {
    let binding = ExecutionBinding::new(
        StorageIdentity::new(*target, *lineage).map_err(|_| invalid())?,
        vec![(tenant, Epoch::new(epoch).map_err(|_| invalid())?)],
    )
    .map_err(|_| invalid())?;
    let pg = PgConfig::new(
        &database.host,
        database.port,
        &database.name,
        &database.user,
        PgPassword::new(config::secret(&database.password_file)?.as_str()),
        PgPrivateCa::from_pem(config::read(&database.ca_file, 1024 * 1024, false)?.to_vec())
            .map_err(|_| invalid())?,
    );
    PgRuntime::connect_producer(pg, crate::lifecycle::RuntimeTimer, binding)
        .await
        .map(Arc::new)
        .map_err(|_| Error::Unavailable(Failure::IdentityStorage))
}
struct RuntimeResource(Arc<PgRuntime>);
impl rss_runtime::ManagedResource for RuntimeResource {
    fn name(&self) -> &str {
        "identity-postgres"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}
struct KdfResource(Arc<PasswordKdf>);
impl rss_runtime::ManagedResource for KdfResource {
    fn name(&self) -> &str {
        "identity-password-kdf"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.0.close();
        self.0.wait_closed().await;
        Ok(())
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub group_facts_max_age_seconds: i64,
    pub state_key_file: PathBuf,
    pub active_credential_key: String,
    pub credential_keys: BTreeMap<String, PathBuf>,
    pub return_targets: BTreeMap<String, String>,
    pub assurance_profiles: Vec<AssuranceProfile>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceProfile {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub keycloak_totp: bool,
}
impl OidcConfig {
    fn federation(
        &self,
        authority: Authority,
        origin: &str,
        instance: InstanceId,
    ) -> Result<rss_identity_postgres::Federation, Error> {
        let oidc = rss_identity_oidc::HttpOidc::new(self.profiles()?).map_err(|_| invalid())?;
        self.federation_using(authority, origin, instance, Arc::new(oidc))
    }
    fn profiles(&self) -> Result<Vec<rss_identity_oidc::TrustedAssuranceProfile>, Error> {
        self.assurance_profiles
            .iter()
            .map(|p| {
                Ok(rss_identity_oidc::TrustedAssuranceProfile {
                    tenant: TenantId::parse(&p.tenant_id).map_err(|_| invalid())?,
                    issuer: p.issuer.clone(),
                    client_id: p.client_id.clone(),
                    keycloak_totp: p.keycloak_totp,
                })
            })
            .collect::<Result<Vec<_>, Error>>()
    }
    fn federation_using(
        &self,
        authority: Authority,
        origin: &str,
        instance: InstanceId,
        oidc: Arc<dyn rss_identity_core::federation::UpstreamOidc>,
    ) -> Result<rss_identity_postgres::Federation, Error> {
        let keys = self
            .credential_keys
            .iter()
            .map(|(id, path)| Ok((id.clone(), *key(path)?)))
            .collect::<Result<Vec<_>, Error>>()?;
        rss_identity_postgres::Federation::new(
            rss_identity_core::groups::GroupFactsMaxAge::new(self.group_facts_max_age_seconds)
                .map_err(|_| invalid())?,
            authority,
            oidc,
            rss_identity_core::federation::StateSigner::new(
                *key(&self.state_key_file)?,
                &instance.to_string(),
            )
            .map_err(|_| invalid())?,
            rss_identity_postgres::FederationConfig {
                callback: format!("{origin}/api/v2/oidc/callback"),
                credential_keys: Arc::new(
                    rss_identity_postgres::CredentialKeys::new(
                        self.active_credential_key.clone(),
                        keys,
                    )
                    .map_err(failure)?,
                ),
                targets: self.return_targets.clone(),
            },
        )
        .map_err(failure)
    }
}
fn key(path: &std::path::Path) -> Result<zeroize::Zeroizing<[u8; 32]>, Error> {
    let text = config::secret(path)?;
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut value = zeroize::Zeroizing::new([0u8; 32]);
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(value)
}
/// Read only the component credential; duplicate cookies fail closed.
pub(crate) fn credential(headers: &HeaderMap) -> Result<SessionSecret, Error> {
    let mut value = None;
    let mut bytes = 0usize;
    for line in headers.get_all(axum::http::header::COOKIE) {
        bytes += line.as_bytes().len();
        if bytes > 8192 {
            return Err(Error::Unauthorized);
        }
        for part in line.to_str().map_err(|_| Error::Unauthorized)?.split(';') {
            if let Some((name, secret)) = part.trim().split_once('=')
                && name == "__Host-identity-session"
            {
                if value.is_some() {
                    return Err(Error::Unauthorized);
                }
                value = Some(SessionSecret::parse(secret.into()).map_err(|_| Error::Unauthorized)?);
            }
        }
    }
    value.ok_or(Error::Unauthorized)
}
/// Only the real accepted gateway peer can supply the single overwritten client IP.
pub(crate) async fn ingress(
    State(gateway): State<std::net::IpAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    if matches!(request.uri().path(), "/livez" | "/readyz") {
        return next.run(request).await;
    }
    let peer = request
        .extensions()
        .get::<rss_axum::AcceptedConnectionInfo<()>>()
        .map(|p| p.socket_peer().ip());
    if peer != Some(gateway) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let forwarded = request
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .collect::<Vec<_>>();
    let source = if forwarded.len() == 1 {
        forwarded[0]
            .to_str()
            .ok()
            .and_then(|v| v.parse::<std::net::IpAddr>().ok())
    } else {
        None
    };
    let Some(source) = source else {
        return StatusCode::FORBIDDEN.into_response();
    };
    for name in [
        "forwarded",
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded-host",
        "x-forwarded-proto",
    ] {
        request.headers_mut().remove(name);
    }
    request
        .extensions_mut()
        .insert(rss_identity_http_axum::ClientAddress(source));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_cookie_credentials_and_malformed_secrets_are_rejected() {
        let value = format!("__Host-identity-session={}", "a".repeat(64));
        let mut headers = HeaderMap::new();
        headers.insert("cookie", value.parse().unwrap());
        assert!(credential(&headers).is_ok());
        headers.append("cookie", value.parse().unwrap());
        assert!(credential(&headers).is_err());
        headers.insert("cookie", format!("{value}; {value}").parse().unwrap());
        assert!(credential(&headers).is_err());
        headers.insert("cookie", "__Host-identity-session=invalid".parse().unwrap());
        assert!(credential(&headers).is_err());
    }
    #[tokio::test]
    async fn forwarding_requires_the_actual_accepted_gateway() -> anyhow::Result<()> {
        use axum::{Extension, middleware, routing::get};
        for (gateway, expected) in [
            ("127.0.0.1", StatusCode::OK),
            ("127.0.0.2", StatusCode::FORBIDDEN),
        ] {
            let router = Router::new()
                .route(
                    "/peer",
                    get(
                        |Extension(peer): Extension<rss_identity_http_axum::ClientAddress>,
                         headers: HeaderMap| async move {
                            assert!(
                                !headers.contains_key("x-forwarded-for")
                                    && !headers.contains_key("forwarded")
                                    && !headers.contains_key("x-real-ip")
                            );
                            peer.0.to_string()
                        },
                    ),
                )
                .layer(middleware::from_fn_with_state(
                    gateway.parse::<std::net::IpAddr>()?,
                    ingress,
                ));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let mut owner = rss_runtime::ShutdownStack::try_new(
                rss_runtime::TotalDrainBudget::new(Duration::from_secs(5))?,
                Arc::new(crate::lifecycle::RuntimeTimer),
            )?;
            owner
                .startup()?
                .stage_task_with_token(rss_axum::serve_http1_registration(
                    listener,
                    router,
                    rss_axum::PlainTransport,
                    "gateway-test",
                    crate::lifecycle::http_policy(),
                ));
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()?;
            let url = format!("http://{address}/peer");
            let response = client
                .get(&url)
                .header("x-forwarded-for", "203.0.113.7")
                .header("forwarded", "for=forged")
                .header("x-real-ip", "forged")
                .send()
                .await?;
            assert_eq!(response.status(), expected);
            if expected == StatusCode::OK {
                assert_eq!(response.text().await?, "203.0.113.7");
            }
            for forwarded in [None, Some("203.0.113.7, 203.0.113.8")] {
                let mut request = client.get(&url);
                if let Some(value) = forwarded {
                    request = request.header("x-forwarded-for", value);
                }
                assert_eq!(request.send().await?.status(), StatusCode::FORBIDDEN);
            }
            drop(client);
            assert!(owner.shutdown().join().await?.is_clean());
        }
        Ok(())
    }
}
