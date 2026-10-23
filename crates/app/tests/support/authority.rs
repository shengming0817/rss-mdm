//! Minimal real authority and protected routes, without Flow or application assembly.
use super::{http::*, runtime::*, *};
use axum::middleware;

pub(crate) struct Authority {
    pub(crate) resources: super::runtime::Resources,
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
        Self::from_config(base).await
    }
    pub(crate) async fn from_config(base: Value) -> Result<Self> {
        let (resources, mut fixture) =
            crate::test_support::runtime::Resources::build(move |resources| {
                Box::pin(async move {
                    let config: Config = serde_json::from_value(base.clone())?;
                    let access = database(&base).await?;
                    let policy = Arc::new(
                        crate::authorization::identity_management::IdentityManagementPolicy::new(
                            INSTANCE,
                        )?,
                    );
                    resources.resource(crate::lifecycle::AccessResource(access.clone()));
                    let identity = Arc::new(
                        crate::identity::Identity::connect(&config, policy, |resource| {
                            resources.acquire(resource)
                        })
                        .await?,
                    );
                    let audit = access.audit_store_fixture(&config.audit).await?;
                    Ok(Self {
                        resources: Default::default(),
                        base,
                        access,
                        identity,
                        audit,
                        credentials: Arc::new(crate::enrollment::credentials::Credentials::new(
                            monotonic(),
                            16,
                        )),
                    })
                })
            })
            .await?;
        fixture.resources = resources;
        Ok(fixture)
    }

    pub(crate) async fn prepared_browser(login: &str) -> Result<Browser> {
        let authority = Self::open().await?;
        let result = authority.browser(login);
        authority.resources.finish(async { result }).await
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
            crate::authorization::http::routes()
                .with_state(Arc::new(crate::authorization::http::HttpState {
                    audit_store: self.audit.clone(),
                }))
                .into_axum(),
        )
    }

    pub(crate) fn enrollment(&self) -> Router {
        Router::new().nest(
            "/api/v1",
            crate::enrollment::http::routes()
                .with_state(Arc::new(crate::enrollment::http::HttpState {
                    channels: Arc::new(crate::test_support::authority::RegistrationChannels),
                    native: Arc::new(crate::enrollment_progress::EnrollmentProgress {
                        sessions: Arc::new(
                            rss_mdm_authorization_service::session::SessionAuthority::new(
                                self.identity.authority.clone(),
                                self.identity.tenant,
                            ),
                        ),
                        windows: None,
                        apple: None,
                    }),
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
                }))
                .into_axum(),
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

pub(crate) struct RegistrationChannels;
impl rss_mdm_management_http::enrollment::channels::Source for RegistrationChannels {
    fn endpoints(&self) -> rss_mdm_management_http::enrollment::channels::PublicEndpoints {
        rss_mdm_management_http::enrollment::channels::PublicEndpoints {
            console: "https://mdm.example.test".into(),
            agent: vec![],
            windows_enrollment: None,
            windows_management: vec![],
            apple_management: None,
        }
    }
    fn status(
        &self,
        _: rss_mdm_registration_service::quotas::Channel,
    ) -> rss_mdm_management_http::enrollment::channels::Status {
        use rss_mdm_management_http::enrollment::channels::*;
        Status {
            availability: Availability::Ready,
            reason: None,
        }
    }
}
