//! Product assembly of the four public Identity components. The database is the authority.
use crate::{
    ConfigIssue, Error, Failure,
    authorization::identity_management::IdentityManagementPolicy,
    config::{self, Config},
};
use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
#[cfg(test)]
use rss_identity_core::session::SessionSecret;
use rss_identity_core::{InstanceId, account::PasswordKdf, session::SessionPolicy};
use rss_identity_postgres::{Authority, AuthorityConfig, AuthorityError};
#[cfg(test)]
use rss_mdm_authorization_service::context::Principal;
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
        AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Unavailable(Failure::IdentityStorage),
    }
}
pub(crate) struct Identity {
    pub(crate) instance: InstanceId,
    pub(crate) authority: Authority,
    pub(crate) tenant: TenantId,
    pub(crate) audit_readiness: Arc<crate::identity_audit::Readiness>,
    routes: Router,
    http: rss_identity_http_axum::HttpConfig,
}
impl Identity {
    pub(crate) fn browser(&self) -> Arc<rss_mdm_management_http::identity::Identity> {
        Arc::new(rss_mdm_management_http::identity::Identity {
            authority: self.authority.clone(),
            http: self.http.clone(),
            tenant: self.tenant,
        })
    }
    pub(crate) async fn connect(
        config: &Config,
        policy: Arc<IdentityManagementPolicy>,
        acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
    ) -> Result<Self, Error> {
        Self::connect_using(config, policy, acquire, OidcConfig::federation).await
    }
    async fn connect_using(
        config: &Config,
        policy: Arc<IdentityManagementPolicy>,
        mut acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
        federation: impl FnOnce(
            &OidcConfig,
            Authority,
            &str,
            InstanceId,
            TenantId,
        ) -> Result<rss_identity_postgres::Federation, Error>,
    ) -> Result<Self, Error> {
        let tenant = TenantId::parse(&config.identity.tenant_id).map_err(|_| invalid())?;
        let instance = InstanceId::parse(&config.identity.instance_id).map_err(|_| invalid())?;
        let runtime = open_runtime(
            &config.identity.database,
            &config.flow.storage.target,
            &config.flow.storage.lineage,
            config.flow.storage.epoch,
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
            let federation = federation(
                oidc,
                authority.clone(),
                &config.product_origin,
                instance,
                tenant,
            )?;
            routes = routes.merge(
                rss_identity_http_axum::federated_router(federation, http.clone())
                    .map_err(failure)?,
            );
        }
        Ok(Self {
            instance,
            authority,
            tenant,
            audit_readiness: Arc::default(),
            routes,
            http,
        })
    }
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn for_oidc_fixture(
        config: &Config,
        policy: Arc<IdentityManagementPolicy>,
    ) -> Result<Self, Error> {
        Self::connect_using(
            config,
            policy,
            |_| {},
            |config, authority, origin, instance, _tenant| {
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

    /// Device enrollment continuations revalidate the credential without renewing idle expiry.
    #[cfg(test)]
    pub(crate) async fn authenticate(&self, secret: SessionSecret) -> Result<Principal, Error> {
        let session = self
            .authority
            .inspect_session(self.tenant, secret, deadline())
            .await
            .map_err(failure)?;
        Principal::new(session).map_err(Error::from)
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
    let (pg, binding) = runtime_inputs(database, target, lineage, epoch, tenant)?;
    PgRuntime::connect_producer(pg, crate::lifecycle::RuntimeTimer, binding)
        .await
        .map(Arc::new)
        .map_err(|_| Error::Unavailable(Failure::IdentityStorage))
}
pub(crate) async fn open_consumer_runtime(
    database: &config::Database,
    target: &[u8; 16],
    lineage: &[u8; 16],
    epoch: i64,
    tenant: TenantId,
) -> Result<Arc<PgRuntime>, Error> {
    let (pg, binding) = runtime_inputs(database, target, lineage, epoch, tenant)?;
    PgRuntime::connect_consumer(pg, crate::lifecycle::RuntimeTimer, binding)
        .await
        .map(Arc::new)
        .map_err(|_| Error::Unavailable(Failure::IdentityStorage))
}
fn runtime_inputs(
    database: &config::Database,
    target: &[u8; 16],
    lineage: &[u8; 16],
    epoch: i64,
    tenant: TenantId,
) -> Result<(PgConfig, ExecutionBinding), Error> {
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
    Ok((pg, binding))
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
    pub private_providers: Vec<PrivateProvider>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceProfile {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub keycloak_totp: bool,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateProvider {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub cidrs: Vec<String>,
}
impl OidcConfig {
    fn private_access(
        &self,
        tenant: TenantId,
    ) -> Result<Vec<rss_identity_oidc::PrivateProviderAccess>, Error> {
        self.private_providers
            .iter()
            .map(|p| {
                let owner = TenantId::parse(&p.tenant_id).map_err(|_| invalid())?;
                if owner != tenant {
                    return Err(invalid());
                }
                Ok(rss_identity_oidc::PrivateProviderAccess {
                    tenant: owner,
                    issuer: p.issuer.clone(),
                    client_id: p.client_id.clone(),
                    cidrs: p
                        .cidrs
                        .iter()
                        .map(|s| s.parse().map_err(|_| invalid()))
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect()
    }
    fn transport(&self, tenant: TenantId) -> Result<rss_identity_oidc::HttpOidc, Error> {
        rss_identity_oidc::HttpOidc::new(self.profiles()?, self.private_access(tenant)?)
            .map_err(|_| invalid())
    }

    fn federation(
        &self,
        authority: Authority,
        origin: &str,
        instance: InstanceId,
        tenant: TenantId,
    ) -> Result<rss_identity_postgres::Federation, Error> {
        let oidc = self.transport(tenant)?;
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
#[path = "../tests/identity/unit.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/identity/mod.rs"]
pub(crate) mod t2;
