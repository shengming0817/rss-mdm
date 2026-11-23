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
use rss_transactional_messaging_postgres::{PgConfig, PgError, PgPassword, PgPrivateCa, PgRuntime};
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
    storage: crate::owner_storage::StorageBinding,
    runtime: Arc<PgRuntime>,

    management: ExecutionBinding,
    rp: rss_identity_postgres::RpGeneration,
    timeout: Duration,
    management_timeout: Duration,
    federation: Option<rss_identity_postgres::Federation>,
}
const TENANT_PREFIXES: [&str; 3] = [
    "/api/v1/identity/tenants/",
    "/api/v1/identity-host/tenants/",
    "/api/v1/tenants/",
];
#[derive(Clone, Copy)]
enum ScopeFailure {
    Malformed,
    Forbidden,
    Unavailable,
    Deadline,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(tag = "code", rename_all = "snake_case")]
enum IdentityScopeFailure {
    IdentityUnavailable,
}
impl ScopeFailure {
    fn product_error(self) -> rss_mdm_management_http::Error {
        use rss_mdm_management_http::{Error, Failure};
        match self {
            Self::Malformed => Error::Malformed,
            Self::Forbidden => Error::Forbidden,
            Self::Unavailable => Error::Unavailable(Failure::IdentityStorage),
            Self::Deadline => Error::RequestDeadline,
        }
    }
    fn identity(self, path: &str) -> bool {
        matches!(self, Self::Unavailable | Self::Deadline) && path.starts_with("/api/v1/identity/")
    }
    fn response(self, path: &str) -> Response {
        let response = if self.identity(path) {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(IdentityScopeFailure::IdentityUnavailable),
            )
                .into_response()
        } else {
            self.product_error().into_response()
        };
        let mut response = response;
        if matches!(self, Self::Deadline) && self.identity(path) {
            response
                .extensions_mut()
                .insert(rss_identity_http_axum::HttpFailure::RequestTimeout);
        }
        let request_id = uuid::Uuid::new_v4();
        let failure = match self {
            Self::Malformed => "malformed_scope",
            Self::Forbidden => "scope_denied",
            Self::Unavailable => "scope_unavailable",
            Self::Deadline => "scope_deadline",
        };
        tracing::warn!(target: "rss_mdm_app::http_scope", event = "mdm_request", %request_id,
            stage = "execution_scope", status = response.status().as_u16(), failure);
        rss_mdm_management_http::boundary::secure(response, request_id)
    }
    fn contract(self, path: &str) -> rss_mdm_http_contract::signature::Response {
        let response = if self.identity(path) {
            rss_mdm_http_contract::signature::Response::json::<IdentityScopeFailure>(503)
        } else {
            self.product_error().response_contract()
        };
        rss_mdm_management_http::boundary::rejection_contract(response)
    }
}
pub(crate) fn scope_rejections(
    _: &str,
    path: &str,
) -> Vec<rss_mdm_http_contract::signature::Response> {
    let mut responses = vec![
        ScopeFailure::Unavailable.contract(path),
        ScopeFailure::Deadline.contract(path),
    ];
    if TENANT_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
        || path.starts_with("/api/v1/tenant-administration/")
    {
        responses.extend([
            ScopeFailure::Malformed.contract(path),
            ScopeFailure::Forbidden.contract(path),
        ]);
    }
    responses
}
// Product-installed coordinates select the SDK scope. The route only identifies which
// installed product context is requested; it cannot author storage, lineage or epoch.
async fn execution_scope(
    State(scope): State<HttpExecution>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let timeout = if parts.uri.path().starts_with("/api/v1/identity/") {
        scope.timeout
    } else {
        scope.management_timeout
    };
    let Ok(mut cutoff) =
        rss_request_context::Deadline::from_timeout(&crate::lifecycle::RuntimeTimer, timeout)
    else {
        return ScopeFailure::Deadline.response(parts.uri.path());
    };
    if let Some(parent) = parts.extensions.get::<rss_request_context::Deadline>() {
        cutoff = cutoff.shortened_to(parent.instant());
    }
    parts.extensions.insert(cutoff);
    parts.extensions.insert(scope.rp);
    let path = parts.uri.path();
    let tenant = if path.starts_with("/api/v1/tenant-administration/") {
        Some(scope.management.tenant())
    } else {
        let locator = TENANT_PREFIXES
            .iter()
            .find_map(|prefix| path.strip_prefix(prefix))
            .and_then(|rest| rest.split('/').next());
        match locator {
            Some(raw) => match TenantId::parse(raw) {
                Ok(tenant) if tenant.to_string() == raw => Some(tenant),
                _ => return ScopeFailure::Malformed.response(path),
            },
            None => None,
        }
    };
    if let Some(tenant) = tenant {
        let binding = if tenant == scope.management.tenant() {
            scope.management
        } else {
            match scope.storage.execution(tenant) {
                Ok(binding) => binding,
                Err(_) => return ScopeFailure::Forbidden.response(path),
            }
        };
        // A missing tenant has no execution fence. Only a confirmed fenced outcome is
        // denied; storage faults and uncertain settlement retain availability semantics.
        let admitted = scope.runtime.local_tx(binding, OperationDeadline::from_cutoff(cutoff, &crate::lifecycle::RuntimeTimer), move |tx| Box::pin(async move {
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT FROM public.mdm_tenants WHERE tenant_id=$1::uuid AND NOT deleted)")
                    .bind(binding.tenant().to_string()).fetch_one(c).await
            })).await
        })).await.fold(Ok, Err, Err, |_| Err(PgError::from(sqlx::Error::Protocol("scope rollback unconfirmed".into()))), |_| Err(PgError::from(sqlx::Error::Protocol("scope commit unconfirmed".into()))), |_| Ok(false));
        match admitted {
            Ok(true) => (),
            Ok(false) => return ScopeFailure::Forbidden.response(path),
            Err(_)
                if cutoff.is_expired(rss_request_context::Clock::now(
                    &crate::lifecycle::RuntimeTimer,
                )) =>
            {
                return ScopeFailure::Deadline.response(path);
            }
            Err(_) => return ScopeFailure::Unavailable.response(path),
        }
        parts.extensions.insert(binding);
        if tenant != scope.management.tenant()
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
            let mut response = ScopeFailure::Unavailable.response(path);
            response
                .extensions_mut()
                .insert(rss_identity_http_axum::HttpFailure::Authority(error));
            return response;
        }
    }
    // OIDC callback carries its original binding in authenticated state, never a fresh locator.
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
    pub(crate) storage: crate::owner_storage::StorageBinding,

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
            storage: self.storage.identity().expect("admitted storage identity"),
            expected_epoch: rss_transactional_messaging::fence::Epoch::new(self.storage.epoch)
                .expect("admitted epoch"),
            rp_generation: self.rp_generation,
        })
    }

    pub(crate) fn browser(&self) -> Arc<rss_mdm_management_http::identity::Identity> {
        Arc::new(rss_mdm_management_http::identity::Identity {
            authority: self.authority.clone(),
            webauthn: self.webauthn.clone(),
            http: self.http.clone(),
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
        let instance = InstanceId::parse(&config.identity.instance_id).map_err(|_| invalid())?;
        let management_tenant = management_tenant(&config.identity.database, instance).await?;
        if management_tenant.to_string() != config.identity.management_tenant {
            return Err(invalid());
        }
        let management_binding = ExecutionBinding::new(
            config.storage_binding.identity()?,
            management_tenant,
            Epoch::new(rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH)
                .map_err(|_| invalid())?,
        );
        let binding = management_binding;

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
                let client = enterprise::Backend::load(input, transport).map_err(|_| invalid())?;
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
            .map(|(id, c)| (id.clone(), (c.tenant(), c.fingerprint().to_owned())))
            .collect();
        let apple = platform
            .as_ref()
            .map(|p| p.clone() as Arc<dyn rss_identity_postgres::platform::PlatformVerifier>);
        let enterprise_platform = config.device_access.as_ref().map(|_| {
            Arc::new(
                rss_mdm_device_access_postgres::enterprise::platform::Verifier::new(
                    &config.product_origin,
                    rss_transactional_messaging::fence::ExecutionBinding::new(
                        binding.storage(),
                        management_tenant,
                        rss_transactional_messaging::fence::Epoch::new(
                            config.storage_binding.epoch,
                        )
                        .expect("compiled positive epoch"),
                    ),
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
            let federation = oidc.federation(
                authority.clone(),
                &config.product_origin,
                instance,
                compiled.transport,
            )?;
            configured_federation = Some(federation.clone());
            routes = routes.merge(
                rss_identity_http_axum::federated_router(federation, http.clone())
                    .map_err(failure)?
                    .route_layer(axum::middleware::from_fn_with_state(
                        management_tenant.to_string(),
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
            storage: config.storage_binding.clone(),

            management_tenant,
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
        envelope.request_timeout = self.request_timeout;
        let bearer = self
            .bearer_routes
            .clone()
            .route_layer(axum::middleware::from_fn_with_state(
                admission,
                rss_mdm_management_http::api_access::admit_bearer,
            ));
        IdentityRoutes(rss_mdm_management_http::authentication_routes(
            self.routes.clone().merge(bearer),
            envelope,
        ))
    }
    pub(crate) fn scope_browser(&self, router: Router, management_timeout: Duration) -> Router {
        router.layer(axum::middleware::from_fn_with_state(
            HttpExecution {
                storage: self.storage.clone(),
                runtime: self.runtime.clone(),

                management: self.management_binding,
                rp: self.rp_generation,
                timeout: self.request_timeout,
                management_timeout,
                federation: self.federation.clone(),
            },
            execution_scope,
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
        origin: &str,
        transport: &policy::Transport,
    ) -> Result<(), Error> {
        rss_identity_core::groups::GroupFactsMaxAge::new(self.group_facts_max_age_seconds)
            .map_err(|_| invalid())?;
        self.transport(transport.build()?)?;
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
    fn private_access(&self) -> Result<Vec<rss_identity_oidc::PrivateProviderAccess>, Error> {
        self.private_providers
            .iter()
            .map(|p| {
                let owner = TenantId::parse(&p.tenant_id).map_err(|_| invalid())?;
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
        policy: rss_identity_oidc::TransportPolicy,
    ) -> Result<rss_identity_oidc::HttpOidc, Error> {
        rss_identity_oidc::HttpOidc::new(self.profiles()?, self.private_access()?, policy)
            .map_err(|_| invalid())
    }

    fn federation(
        &self,
        authority: Authority,
        origin: &str,
        instance: InstanceId,
        policy: rss_identity_oidc::TransportPolicy,
    ) -> Result<rss_identity_postgres::Federation, Error> {
        let oidc = self.transport(policy)?;
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
        && path.split('/').next() == Some(tenant.as_str())
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
