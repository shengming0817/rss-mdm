//! Minimal real authority and protected routes, without Flow or application assembly.
use super::*;
use axum::middleware;

pub(crate) struct Authority {
    pub(crate) base: Value,
    pub(crate) access: Arc<crate::Database>,
    pub(crate) identity: Arc<crate::identity::Identity>,
    pub(crate) credentials: Arc<crate::enrollment::credentials::Credentials>,
    pub(crate) audit: Arc<rss_mdm_audit_integration::AuditStore>,
}
impl Authority {
    pub(crate) async fn open() -> Result<Self> {
        let base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        let config: Config = serde_json::from_value(base.clone())?;
        let access = database(&base).await?;
        let policy = Arc::new(
            crate::authorization::identity_management::IdentityManagementPolicy::new(
                case_tenant(),
                INSTANCE,
                config.identity_management.clone(),
            )?,
        );
        let identity = Arc::new(crate::identity::Identity::connect(&config, policy, |_| {}).await?);
        let audit = access.audit_store(&config.audit).await?;
        Ok(Self {
            base,
            access,
            identity,
            audit,
            credentials: Arc::new(crate::enrollment::credentials::Credentials::new(
                monotonic(),
                16,
            )),
        })
    }

    pub(crate) fn browser(&self, login: &str) -> Result<Browser> {
        let secret = identity::credential(&self.identity, login)?;
        Ok(Browser {
            cookies: BTreeMap::from([("__Host-identity-session".into(), secret.expose().into())]),
            csrf: Some(secret.csrf()),
            ..Browser::default()
        })
    }

    pub(crate) fn authorization(&self) -> Router {
        Router::new().nest(
            "/api/v1",
            crate::authorization::http::routes().with_state(Arc::new(
                crate::authorization::http::HttpState {
                    audit_store: self.audit.clone(),
                },
            )),
        )
    }

    pub(crate) fn enrollment(&self) -> Router {
        Router::new().nest(
            "/api/v3",
            crate::enrollment::http::routes().with_state(Arc::new(
                crate::enrollment::http::HttpState {
                    service: Arc::new(crate::enrollment::EnrollmentService::new(
                        self.access.registration(),
                        self.credentials.clone(),
                        self.audit.clone(),
                    )),
                    devices: Arc::new(crate::device::DeviceService::new(
                        self.access.registration(),
                        case_tenant().into(),
                        self.audit.clone(),
                    )),
                    apple: false,
                    windows: true,
                },
            )),
        )
    }

    pub(crate) fn router(&self, routes: Router) -> Result<Router> {
        self.router_with_public(routes, Router::new())
    }

    pub(crate) fn router_with_public(&self, routes: Router, public: Router) -> Result<Router> {
        let requests = Arc::new(tokio::sync::Semaphore::new(32));
        Ok(routes
            .route_layer(middleware::from_fn_with_state(
                Arc::new(crate::authorization::http::AuthenticationState {
                    identity: self.identity.browser(),
                    access: self.access.authorization_store(),
                    requests: requests.clone(),
                }),
                crate::authorization::http::protect,
            ))
            .layer(axum::extract::DefaultBodyLimit::max(16384))
            .layer(middleware::from_fn_with_state(
                rss_mdm_management_http::boundary::Envelope {
                    admission: Arc::new(tokio::sync::Semaphore::new(32)),
                    host: "mdm.example.test".into(),
                    clock: monotonic(),
                    audit_store: self.audit.clone(),
                    requests,
                    tenant: case_tenant().into(),
                },
                rss_mdm_management_http::boundary::admit,
            ))
            .merge(public)
            .merge(self.identity.routes())
            .layer(axum::Extension(rss_identity_http_axum::ClientAddress(
                "127.0.0.1".parse()?,
            ))))
    }
}

pub(crate) async fn reader(base: &Value) -> Result<Arc<InventoryReader>> {
    let config: Config = serde_json::from_value(base.clone())?;
    Ok(Arc::new(
        InventoryReader::connect(
            config
                .access_database
                .options()?
                .username("mdm_api")
                .password("api-fixture"),
        )
        .await?,
    ))
}
