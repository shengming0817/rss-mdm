//! Product assembly of the four public Identity components. The database is the authority.
use crate::{
    ConfigIssue, Error, Failure,
    authorization::identity_management::IdentityManagementPolicy,
    config::{self, Config},
};
use axum::{
    Router,
    extract::{MatchedPath, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
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

// MDM owns attribute visibility. The component's raw observation endpoint must
// not bypass that projection; account-local authority management remains available.
async fn product_profile_boundary(request: Request, next: Next) -> Response {
    if request
        .extensions()
        .get::<MatchedPath>()
        .is_some_and(|path| path.as_str() == "/api/v1/identity/tenants/{tenant}/profile")
    {
        return (
            StatusCode::NOT_FOUND,
            [("cache-control", "no-store")],
            axum::Json(serde_json::json!({"code":"not_found"})),
        )
            .into_response();
    }
    next.run(request).await
}

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
    pub(crate) platform: Option<Arc<rss_mdm_apple_channel::platform_sso::bridge::Verifier>>,
    pub(crate) instance: InstanceId,
    pub(crate) authority: Authority,
    pub(crate) tenant: TenantId,
    pub(crate) management_tenant: TenantId,
    pub(crate) tenant_administration: Option<Arc<crate::tenant_registry::http::Service>>,
    pub(crate) audit_readiness: Arc<crate::audit_health::Readiness>,
    pub(crate) federation: Option<rss_identity_postgres::Federation>,
    routes: Router,
    bearer_routes: Router,
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
    pub(crate) fn management_browser(&self) -> Arc<rss_mdm_management_http::identity::Identity> {
        Arc::new(rss_mdm_management_http::identity::Identity {
            authority: self.authority.clone(),
            http: self.http.clone(),
            tenant: self.management_tenant,
        })
    }
    pub(crate) async fn connect(
        config: &Config,
        policy: Arc<IdentityManagementPolicy>,
        platform: Option<Arc<rss_mdm_apple_channel::platform_sso::bridge::Verifier>>,
        acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
    ) -> Result<Self, Error> {
        Self::connect_using(
            config,
            policy,
            platform,
            acquire,
            |authority| authority,
            OidcConfig::federation,
        )
        .await
    }
    async fn connect_using(
        config: &Config,
        policy: Arc<IdentityManagementPolicy>,
        platform: Option<Arc<rss_mdm_apple_channel::platform_sso::bridge::Verifier>>,
        mut acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
        configure_authority: impl FnOnce(Authority) -> Authority,
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
        let management_tenant = management_tenant(&config.identity.database, instance).await?;
        let management_epoch = rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH;
        let mut tenants = vec![(tenant, config.flow.storage.epoch)];
        if tenant != management_tenant {
            tenants.push((management_tenant, management_epoch));
        } else if config.flow.storage.epoch != management_epoch {
            return Err(invalid());
        }
        let runtime = open_runtime(
            &config.identity.database,
            &config.flow.storage.target,
            &config.flow.storage.lineage,
            &tenants,
        )
        .await?;
        acquire(rss_runtime::DynManagedResource::new_box(RuntimeResource(
            runtime.clone(),
        )));
        let kdf = Arc::new(PasswordKdf::new());
        acquire(rss_runtime::DynManagedResource::new_box(KdfResource(
            kdf.clone(),
        )));
        let mut options = authority_config(
            instance,
            tenants.iter().map(|(tenant, _)| *tenant).collect(),
        )?;
        if let Some(platform) = &platform {
            options = options.with_platform(platform.clone());
        }
        let authority =
            Authority::connect_runtime(runtime, kdf.clone(), options, policy.clone(), deadline())
                .await
                .map_err(failure)?;
        let authority = configure_authority(authority);
        let tenant_administration =
            crate::tenant_registry::http::Service::connect(config, management_tenant, kdf, policy)
                .await?;
        if let Some(service) = &tenant_administration {
            acquire(rss_runtime::DynManagedResource::new_box(
                crate::tenant_registry::http::Resource(service.clone()),
            ));
        }
        let http = rss_identity_http_axum::HttpConfig::new(
            &config.product_origin,
            Duration::from_secs(10),
        )
        .map_err(|_| invalid())?;
        let mut routes = rss_identity_http_axum::router(authority.clone(), http.clone())
            .map_err(failure)?
            .route_layer(axum::middleware::from_fn(product_profile_boundary));
        let bearer_routes = rss_identity_http_axum::bearer_router(authority.clone(), http.clone())
            .map_err(failure)?;
        let mut configured_federation = None;
        if let Some(oidc) = &config.identity.oidc {
            oidc.require_business_tenant(&config.identity.tenant_id)?;
            let federation = federation(
                oidc,
                authority.clone(),
                &config.product_origin,
                instance,
                tenant,
            )?;
            configured_federation = Some(federation.clone());
            routes = routes.merge(
                rss_identity_http_axum::federated_router(federation, http.clone())
                    .map_err(failure)?
                    .route_layer(axum::middleware::from_fn_with_state(
                        config.identity.tenant_id.clone(),
                        business_federation,
                    )),
            );
        }
        Ok(Self {
            platform,
            instance,
            authority,
            tenant,
            management_tenant,
            tenant_administration,
            audit_readiness: Arc::default(),
            federation: configured_federation,
            routes,
            bearer_routes,
            http,
        })
    }
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn for_oidc_fixture(
        config: &Config,
        policy: Arc<IdentityManagementPolicy>,
        fact_time: rss_identity_postgres::ControlledFactTime,
        acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
    ) -> Result<Self, Error> {
        Self::connect_using(
            config,
            policy,
            None,
            acquire,
            |authority| authority.with_fact_time(fact_time),
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
    pub(crate) fn bearer_routes(&self) -> Router {
        self.bearer_routes.clone()
    }

    /// Device enrollment continuations revalidate the credential without renewing idle expiry.
    #[cfg(test)]
    pub(crate) async fn authenticate(
        &self,
        credential: rss_mdm_authorization_service::credential::RequestCredential,
    ) -> Result<Principal, Error> {
        let rss_mdm_authorization_service::credential::RequestCredential::Cookie(secret) =
            credential
        else {
            return Err(Error::Forbidden);
        };
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
    tenants: Vec<TenantId>,
) -> Result<AuthorityConfig, Error> {
    AuthorityConfig::new(
        instance,
        tenants,
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
    tenants: &[(TenantId, i64)],
) -> Result<Arc<PgRuntime>, Error> {
    let (pg, binding) = runtime_inputs(database, target, lineage, tenants)?;
    PgRuntime::connect_producer(pg, crate::lifecycle::RuntimeTimer, binding)
        .await
        .map(Arc::new)
        .map_err(|_| Error::Unavailable(Failure::IdentityStorage))
}
pub(crate) async fn open_consumer_runtime(
    database: &config::Database,
    target: &[u8; 16],
    lineage: &[u8; 16],
    tenants: &[(TenantId, i64)],
) -> Result<Arc<PgRuntime>, Error> {
    let (pg, binding) = runtime_inputs(database, target, lineage, tenants)?;
    PgRuntime::connect_consumer(pg, crate::lifecycle::RuntimeTimer, binding)
        .await
        .map(Arc::new)
        .map_err(|_| Error::Unavailable(Failure::IdentityStorage))
}
fn runtime_inputs(
    database: &config::Database,
    target: &[u8; 16],
    lineage: &[u8; 16],
    tenants: &[(TenantId, i64)],
) -> Result<(PgConfig, ExecutionBinding), Error> {
    let binding = ExecutionBinding::new(
        StorageIdentity::new(*target, *lineage).map_err(|_| invalid())?,
        tenants
            .iter()
            .map(|(tenant, epoch)| Ok((*tenant, Epoch::new(*epoch).map_err(|_| invalid())?)))
            .collect::<Result<Vec<_>, Error>>()?,
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

/// Read installation-owned admission coordinates; this connection never owns application state.
pub(crate) async fn management_tenant(
    database: &config::Database,
    instance: InstanceId,
) -> Result<TenantId, Error> {
    use sqlx::Connection;
    let mut connection = tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::PgConnection::connect_with(&database.options()?),
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::IdentityStorage))?
    .map_err(|_| Error::Unavailable(Failure::IdentityStorage))?;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let raw: Option<String> = sqlx::query_scalar("SELECT management_tenant_id::text FROM public.mdm_installation WHERE singleton AND instance_id=$1::uuid")
            .bind(instance.to_string()).fetch_optional(&mut connection).await.map_err(|_| Error::Unavailable(Failure::IdentityStorage))?;
        TenantId::parse(&raw.ok_or_else(invalid)?).map_err(|_| invalid())
    }).await.map_err(|_| Error::Unavailable(Failure::IdentityStorage)).and_then(|r| r);
    let closed = matches!(
        tokio::time::timeout(Duration::from_secs(5), connection.close()).await,
        Ok(Ok(()))
    );
    match result {
        Err(error) => Err(error),
        Ok(tenant) if closed => Ok(tenant),
        Ok(_) => Err(Error::Unavailable(Failure::IdentityStorage)),
    }
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
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceProfile {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub keycloak_totp: bool,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateProvider {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub cidrs: Vec<String>,
}
impl OidcConfig {
    pub(crate) fn validate_deployment(&self, tenant: &str, origin: &str) -> Result<(), Error> {
        self.require_business_tenant(tenant)?;
        rss_identity_core::groups::GroupFactsMaxAge::new(self.group_facts_max_age_seconds)
            .map_err(|_| invalid())?;
        self.transport(TenantId::parse(tenant).map_err(|_| invalid())?)?;
        key(&self.state_key_file)?;
        rss_identity_postgres::FederationConfig {
            callback: format!("{origin}/api/v1/identity/oidc/callback"),
            credential_keys: Arc::new(self.credential_keys()?),
            targets: self.return_targets.clone(),
        }
        .validate()
        .map_err(failure)
    }
    pub(crate) fn credential_keys(&self) -> Result<rss_identity_postgres::CredentialKeys, Error> {
        let keys = self
            .credential_keys
            .iter()
            .map(|(id, path)| Ok((id.clone(), *key(path)?)))
            .collect::<Result<Vec<_>, Error>>()?;
        rss_identity_postgres::CredentialKeys::new(self.active_credential_key.clone(), keys)
            .map_err(failure)
    }
    fn require_business_tenant(&self, tenant: &str) -> Result<(), Error> {
        if self
            .assurance_profiles
            .iter()
            .any(|profile| profile.tenant_id != tenant)
            || self
                .private_providers
                .iter()
                .any(|provider| provider.tenant_id != tenant)
        {
            return Err(invalid());
        }
        Ok(())
    }
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
                callback: format!("{origin}/api/v1/identity/oidc/callback"),
                credential_keys: Arc::new(self.credential_keys()?),
                targets: {
                    let mut targets = self.return_targets.clone();
                    let bridge = format!("{origin}/api/v1/apple/account-enrollment/authenticate");
                    if targets
                        .get("apple-account-enrollment")
                        .is_some_and(|v| *v != bridge)
                    {
                        return Err(invalid());
                    }
                    targets.insert("apple-account-enrollment".into(), bridge);
                    targets
                },
            },
        )
        .map_err(failure)
    }
}
async fn business_federation(
    State(tenant): State<String>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(path) = request
        .uri()
        .path()
        .strip_prefix("/api/v1/identity/tenants/")
        && path.split('/').next() != Some(tenant.as_str())
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}
pub(crate) fn key(path: &std::path::Path) -> Result<zeroize::Zeroizing<[u8; 32]>, Error> {
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
#[cfg(test)]
#[path = "../tests/identity/unit.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/identity/mod.rs"]
pub(crate) mod t2;
