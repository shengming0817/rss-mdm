pub(crate) mod policy;
use rss_mdm_device_access_runtime::enterprise;
// Product assembly of the four public Identity components. The database is the authority.
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
use rss_identity_core::{InstanceId, account::PasswordKdf};
use rss_identity_postgres::{Authority, AuthorityConfig, AuthorityError};

use rss_request_context::TenantId;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::OperationDeadline,
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
/// Only this owner can introduce Identity's external SDK surface into the browser host.
pub(crate) struct IdentityRoutes(Router);
impl IdentityRoutes {
    pub(crate) fn merge(self, product: Router) -> Router {
        product.merge(self.0)
    }
}

#[derive(Clone)]
struct HttpExecution {
    business: ExecutionBinding,
    management: ExecutionBinding,
    rp: rss_identity_postgres::RpGeneration,
    timeout: Duration,
    federation: Option<rss_identity_postgres::Federation>,
}
// Product-installed coordinates select the SDK scope. The route only identifies which
// installed product context is requested; it cannot author storage, lineage or epoch.
async fn execution_scope(
    State(scope): State<HttpExecution>,
    request: Request,
    next: Next,
) -> Response {
    use axum::extract::{FromRequestParts, Path};
    let (mut parts, body) = request.into_parts();
    let Ok(mut cutoff) =
        rss_request_context::Deadline::from_timeout(&crate::lifecycle::RuntimeTimer, scope.timeout)
    else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Some(parent) = parts.extensions.get::<rss_request_context::Deadline>() {
        cutoff = cutoff.shortened_to(parent.instant());
    }
    parts.extensions.insert(cutoff);
    parts.extensions.insert(scope.rp);
    if let Ok(Path(parameters)) =
        Path::<BTreeMap<String, String>>::from_request_parts(&mut parts, &()).await
        && let Some(raw) = parameters.get("tenant")
    {
        let Ok(tenant) = TenantId::parse(raw) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let binding = if tenant == scope.business.tenant() {
            scope.business
        } else if tenant == scope.management.tenant() {
            scope.management
        } else {
            return StatusCode::FORBIDDEN.into_response();
        };
        parts.extensions.insert(binding);
        let path = parts.uri.path();
        if binding == scope.business
            && (path.contains("/oidc/")
                || path.ends_with("/login-options")
                || path.ends_with("/session/security"))
            && let Some(federation) = &scope.federation
            && let Err(error) = federation
                .reconcile_assurance_profiles(
                    binding,
                    OperationDeadline::from_cutoff(cutoff, &crate::lifecycle::RuntimeTimer),
                )
                .await
        {
            let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
            response
                .extensions_mut()
                .insert(rss_identity_http_axum::HttpFailure::Authority(error));
            return response;
        }
    }
    next.run(Request::from_parts(parts, body)).await
}
pub(crate) struct Identity {
    pub(crate) enterprise_administrators: BTreeMap<
        uuid::Uuid,
        Arc<rss_mdm_device_access_postgres::enterprise::keycloak::Administrator>,
    >,
    pub(crate) enterprise_platform:
        Option<Arc<rss_mdm_device_access_postgres::enterprise::platform::Verifier>>,
    pub(crate) enterprise_clients:
        BTreeMap<String, Arc<dyn rss_mdm_device_access_postgres::enterprise::broker::Client>>,
    pub(crate) runtime: Arc<PgRuntime>,
    pub(crate) webauthn: rss_identity_postgres::WebauthnAuthority,
    pub(crate) platform:
        Option<Arc<rss_mdm_device_access_postgres::platform_sso::bridge::Verifier>>,
    pub(crate) instance: InstanceId,
    pub(crate) authority: Authority,
    pub(crate) tenant: TenantId,
    pub(crate) binding: ExecutionBinding,
    pub(crate) management_binding: ExecutionBinding,
    pub(crate) rp_generation: rss_identity_postgres::RpGeneration,
    pub(crate) management_tenant: TenantId,
    pub(crate) tenant_administration: Option<Arc<crate::administration::tenants::service::Service>>,
    pub(crate) federation: Option<rss_identity_postgres::Federation>,
    routes: Router,
    bearer_routes: Router,
    http: rss_identity_http_axum::HttpConfig,
    request_timeout: Duration,
    pub(crate) request_budget: rss_axum::RequestBudget,
    pub(crate) profile_source_page_size: u16,
}
impl Identity {
    pub(crate) fn da_browser(&self) -> Arc<rss_mdm_device_access_http::identity::Identity> {
        Arc::new(rss_mdm_device_access_http::identity::Identity {
            enterprise_clients: self.enterprise_clients.clone(),
            enterprise_administrators: self.enterprise_administrators.clone(),
            authority: self.authority.clone(),
            webauthn: self.webauthn.clone(),
            http: self.http.clone(),
            tenant: self.tenant,
            binding: self.binding,
            rp_generation: self.rp_generation,
        })
    }

    pub(crate) fn browser(&self) -> Arc<rss_mdm_management_http::identity::Identity> {
        Arc::new(rss_mdm_management_http::identity::Identity {
            authority: self.authority.clone(),
            webauthn: self.webauthn.clone(),
            http: self.http.clone(),
            tenant: self.tenant,
            binding: self.binding,
            rp_generation: self.rp_generation,
        })
    }
    pub(crate) fn management_browser(&self) -> Arc<rss_mdm_management_http::identity::Identity> {
        Arc::new(rss_mdm_management_http::identity::Identity {
            authority: self.authority.clone(),
            webauthn: self.webauthn.clone(),
            http: self.http.clone(),
            tenant: self.management_tenant,
            binding: self.management_binding,
            rp_generation: self.rp_generation,
        })
    }
    pub(crate) async fn connect(
        config: &Config,
        compiled: &policy::Compiled,
        policy: Arc<IdentityManagementPolicy>,
        platform: Option<Arc<rss_mdm_device_access_postgres::platform_sso::bridge::Verifier>>,
        mut acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
    ) -> Result<Self, Error> {
        let cutoff = rss_request_context::Deadline::from_timeout(
            &crate::lifecycle::RuntimeTimer,
            compiled.startup,
        )
        .map_err(|_| invalid())?;
        let tenant = TenantId::parse(&config.identity.tenant_id).map_err(|_| invalid())?;
        let instance = InstanceId::parse(&config.identity.instance_id).map_err(|_| invalid())?;
        let management_tenant = management_tenant(&config.identity.database, instance).await?;
        let management_epoch = rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH;
        if tenant == management_tenant && config.storage_binding.epoch != management_epoch {
            return Err(invalid());
        }
        let binding = config.storage_binding.execution(tenant)?;
        let management_binding = ExecutionBinding::new(
            binding.storage(),
            management_tenant,
            Epoch::new(management_epoch).map_err(|_| invalid())?,
        );
        let rp_generation = compiled.rp;
        let runtime = open_runtime(
            &config.identity.database,
            &config.storage_binding.target,
            &config.storage_binding.lineage,
            crate::background::IDENTITY_CONNECTIONS,
        )
        .await?;
        acquire(rss_runtime::DynManagedResource::new_box(RuntimeResource(
            runtime.clone(),
        )));
        let kdf = compiled.kdf.clone();
        acquire(rss_runtime::DynManagedResource::new_box(KdfResource {
            kdf: kdf.clone(),
            timeout: compiled.drain,
        }));
        let mut options = compiled.authority.clone();
        let mut enterprise_clients: BTreeMap<
            String,
            Arc<dyn rss_mdm_device_access_postgres::enterprise::broker::Client>,
        > = BTreeMap::new();
        if let Some(deployment) = config
            .identity
            .enterprise
            .as_ref()
            .filter(|_| config.device_access.is_some())
        {
            if deployment.clients.is_empty() || deployment.clients.len() > 64 {
                return Err(invalid());
            }
            let transport = compiled.transport;
            for input in &deployment.clients {
                let client =
                    enterprise::Backend::load(input, tenant, transport).map_err(|_| invalid())?;
                if enterprise_clients
                    .insert(input.target.id.clone(), Arc::new(client))
                    .is_some()
                {
                    return Err(invalid());
                }
            }
            let pem = config::read(&deployment.signing_key_file, 16384, true)?;
            let signer = Arc::new(
                rss_identity_oidc::enterprise::Es256EnterpriseSigner::new(
                    deployment.key_id.clone(),
                    &pem,
                )
                .map_err(|_| invalid())?,
            );
            options = options.with_enterprise(
                rss_identity_postgres::platform::EnterpriseConfig::new(
                    deployment
                        .clients
                        .iter()
                        .map(|c| c.target.clone())
                        .collect(),
                    signer,
                )
                .map_err(failure)?,
            );
        }
        let mut enterprise_administrators = BTreeMap::new();
        if let Some(deployment) = config
            .identity
            .enterprise
            .as_ref()
            .filter(|_| config.device_access.is_some())
        {
            if deployment.administrators.len() > 64 {
                return Err(invalid());
            }
            for entry in &deployment.administrators {
                let secret = config::secret(&entry.client_secret_file)?;
                let ca = entry
                    .private_ca_file
                    .as_ref()
                    .map(|p| config::read(p, 65536, false))
                    .transpose()?;
                let admin =
                    rss_mdm_device_access_postgres::enterprise::keycloak::Administrator::new(
                        entry.configuration.clone(),
                        secret,
                        ca.as_deref().map(|v| v.as_slice()),
                    )
                    .map_err(|_| invalid())?;
                if enterprise_administrators
                    .insert(admin.provider, Arc::new(admin))
                    .is_some()
                {
                    return Err(invalid());
                }
            }
        }
        let target_fingerprints = enterprise_clients
            .iter()
            .map(|(id, c)| (id.clone(), c.fingerprint().to_owned()))
            .collect();
        let apple = platform
            .as_ref()
            .map(|p| p.clone() as Arc<dyn rss_identity_postgres::platform::PlatformVerifier>);
        let enterprise_platform = config.device_access.as_ref().map(|_| {
            Arc::new(
                rss_mdm_device_access_postgres::enterprise::platform::Verifier::new(
                    &config.product_origin,
                    binding,
                    runtime.clone(),
                    apple,
                    target_fingerprints,
                ),
            )
        });
        if let Some(verifier) = &enterprise_platform {
            options = options.with_platform(verifier.clone());
        }
        let authority = Authority::connect_runtime(
            runtime.clone(),
            kdf.clone(),
            options,
            binding,
            policy.clone(),
            OperationDeadline::from_cutoff(cutoff, &crate::lifecycle::RuntimeTimer),
        )
        .await
        .map_err(failure)?;
        let tenant_administration = crate::administration::tenants::service::Service::connect(
            config,
            management_tenant,
            kdf,
            compiled.authority.clone(),
            cutoff,
            policy,
        )
        .await?;
        if let Some(service) = &tenant_administration {
            acquire(rss_runtime::DynManagedResource::new_box(
                crate::lifecycle::TenantResource(service.clone()),
            ));
        }
        let http =
            rss_identity_http_axum::HttpConfig::new(&config.product_origin, compiled.request)
                .map_err(|_| invalid())?;
        let origin = url::Url::parse(&config.product_origin).map_err(|_| invalid())?;
        let rp = origin.host_str().ok_or_else(invalid)?.to_owned();
        let webauthn = rss_identity_postgres::WebauthnAuthority::new(authority.clone(), rp, origin)
            .map_err(failure)?;
        let mut routes = rss_identity_http_axum::router(authority.clone(), http.clone())
            .map_err(failure)?
            .merge(
                rss_identity_http_axum::webauthn_router(webauthn.clone(), http.clone())
                    .map_err(failure)?,
            )
            .route_layer(axum::middleware::from_fn(product_profile_boundary));
        let bearer_routes = rss_identity_http_axum::bearer_router(authority.clone(), http.clone())
            .map_err(failure)?;
        let mut configured_federation = None;
        if let Some(oidc) = &config.identity.oidc {
            oidc.require_business_tenant(&config.identity.tenant_id)?;
            let federation = oidc.federation(
                authority.clone(),
                &config.product_origin,
                instance,
                tenant,
                compiled.transport,
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
            profile_source_page_size: config.identity.runtime.profile.source_page_size,
            enterprise_platform,
            enterprise_administrators,
            enterprise_clients,
            runtime,
            webauthn,
            platform,
            instance,
            authority,
            tenant,
            management_tenant,
            binding,
            management_binding,
            rp_generation,
            tenant_administration,
            federation: configured_federation,
            routes,
            bearer_routes,
            http,
            request_timeout: compiled.request,
            request_budget: rss_axum::RequestBudget::new(compiled.request)
                .map_err(|_| invalid())?,
        })
    }

    pub(crate) fn http_routes(
        &self,
        admission: Arc<rss_mdm_management_http::api_access::BearerAdmission>,
        mut envelope: rss_mdm_management_http::boundary::Envelope,
    ) -> IdentityRoutes {
        envelope.request_budget = self.request_budget;
        let bearer = self
            .bearer_routes
            .clone()
            .route_layer(axum::middleware::from_fn_with_state(
                admission,
                rss_mdm_management_http::api_access::admit_bearer,
            ));
        IdentityRoutes(rss_mdm_management_http::authentication_routes(
            self.routes
                .clone()
                .merge(bearer)
                .route_layer(axum::middleware::from_fn_with_state(
                    HttpExecution {
                        business: self.binding,
                        management: self.management_binding,
                        rp: self.rp_generation,
                        timeout: self.request_timeout,
                        federation: self.federation.clone(),
                    },
                    execution_scope,
                )),
            envelope,
        ))
    }
}
pub(crate) async fn open_runtime(
    database: &config::Database,
    target: &[u8; 16],
    lineage: &[u8; 16],
    connections: u32,
) -> Result<Arc<PgRuntime>, Error> {
    let (pg, binding) = runtime_inputs(database, target, lineage)?;
    PgRuntime::connect_producer(
        pg.with_pool_limits(0, connections),
        crate::lifecycle::RuntimeTimer,
        binding,
    )
    .await
    .map(Arc::new)
    .map_err(|_| Error::Unavailable(Failure::IdentityStorage))
}
pub(crate) fn runtime_inputs(
    database: &config::Database,
    target: &[u8; 16],
    lineage: &[u8; 16],
) -> Result<(PgConfig, StorageIdentity), Error> {
    let binding = StorageIdentity::new(*target, *lineage).map_err(|_| invalid())?;
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
struct KdfResource {
    kdf: Arc<PasswordKdf>,
    timeout: Duration,
}
impl rss_runtime::ManagedResource for KdfResource {
    fn name(&self) -> &str {
        "identity-password-kdf"
    }
    fn shutdown_timeout(&self) -> Duration {
        self.timeout
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.kdf.close();
        self.kdf.wait_closed().await;
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
    pub(crate) fn validate_deployment(
        &self,
        tenant: &str,
        origin: &str,
        transport: &policy::Transport,
    ) -> Result<(), Error> {
        self.require_business_tenant(tenant)?;
        rss_identity_core::groups::GroupFactsMaxAge::new(self.group_facts_max_age_seconds)
            .map_err(|_| invalid())?;
        self.transport(
            TenantId::parse(tenant).map_err(|_| invalid())?,
            transport.build()?,
        )?;
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
    fn transport(
        &self,
        tenant: TenantId,
        policy: rss_identity_oidc::TransportPolicy,
    ) -> Result<rss_identity_oidc::HttpOidc, Error> {
        rss_identity_oidc::HttpOidc::new(self.profiles()?, self.private_access(tenant)?, policy)
            .map_err(|_| invalid())
    }

    fn federation(
        &self,
        authority: Authority,
        origin: &str,
        instance: InstanceId,
        tenant: TenantId,
        policy: rss_identity_oidc::TransportPolicy,
    ) -> Result<rss_identity_postgres::Federation, Error> {
        let oidc = self.transport(tenant, policy)?;
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
            rss_identity_postgres::StateSigner::new(
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

/// Installed assertion identities and signer. RP policy/callbacks remain product-owned.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseDeployment {
    pub key_id: String,
    pub signing_key_file: PathBuf,
    pub clients: Vec<enterprise::Configuration>,
    pub administrators: Vec<EnterpriseAdministrator>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseAdministrator {
    pub configuration: rss_mdm_device_access_postgres::enterprise::keycloak::Configuration,
    pub client_secret_file: PathBuf,
    pub private_ca_file: Option<PathBuf>,
}
