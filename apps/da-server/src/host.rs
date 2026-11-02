//! Concrete DA composition and process lifetime. Every created resource enters the RSS scope.
use crate::{
    Error, Result,
    config::{Config, Database, Installation, Listener},
};

use rss_identity_core::{InstanceId, account::PasswordKdf, session::SessionPolicy};

use rss_identity_postgres::{Authority, AuthorityConfig};

use rss_mdm_device_access_http as http;

use rss_mdm_device_access_runtime as da;

use rss_mdm_install_support::{
    StorageProfile,
    files::{read, secret},
};

use rss_runtime::{
    DynManagedResource, LifecycleScope, ManagedResource, ScopeExit, TotalDrainBudget,
};

use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    policy::OperationDeadline,
};

use rss_transactional_messaging_postgres::{PgConfig, PgPassword, PgPrivateCa, PgRuntime};

use std::{collections::BTreeMap, sync::Arc, time::Duration};

const DA: StorageProfile = StorageProfile::Da;

pub struct Timer;

impl rss_request_context::Clock for Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "concrete DA host owns the Tokio clock domain"
    )]
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl rss_request_context::ExecutionTimer for Timer {
    async fn sleep_until(&self, d: rss_request_context::Deadline) {
        tokio::time::sleep_until(d.instant().into()).await
    }
}
impl rss_mdm_registration_service::certificate_issuance::Clock for Timer {
    fn unix_seconds(&self) -> std::result::Result<i64, rss_mdm_registration_service::Error> {
        Ok(now())
    }
}
pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
pub fn deadline() -> OperationDeadline {
    OperationDeadline::from_remaining(Duration::from_secs(10))
}
pub struct Pool(pub sqlx::PgPool);

impl ManagedResource for Pool {
    fn name(&self) -> &str {
        "da-access"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;

        Ok(())
    }
}
pub struct RuntimeResource(pub Arc<PgRuntime>);

impl ManagedResource for RuntimeResource {
    fn name(&self) -> &str {
        "da-transaction-runtime"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;

        Ok(())
    }
}
pub struct Kdf(pub Arc<PasswordKdf>);

impl ManagedResource for Kdf {
    fn name(&self) -> &str {
        "da-password-kdf"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.close();

        self.0.wait_closed().await;

        Ok(())
    }
}
struct Requests([Arc<tokio::sync::Semaphore>; 2]);

impl ManagedResource for Requests {
    fn name(&self) -> &str {
        "da-request-completion"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(15)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        for s in &self.0 {
            s.close();
        }
        while self.0[0].available_permits() != 32 || self.0[1].available_permits() != 16 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }
}
pub async fn runtime(db: &Database, i: &Installation) -> Result<Arc<PgRuntime>> {
    let binding = ExecutionBinding::new(
        StorageIdentity::new(i.target, i.lineage).map_err(|_| Error::Configuration)?,
        i.tenants()?
            .into_iter()
            .map(|(t, e)| Ok((t, Epoch::new(e).map_err(|_| Error::Configuration)?)))
            .collect::<Result<Vec<_>>>()?,
    )
    .map_err(|_| Error::Configuration)?;

    let pg = PgConfig::new(
        &db.host,
        db.port,
        &db.name,
        &db.user,
        PgPassword::new(
            secret(&db.password_file)
                .map_err(|_| Error::Configuration)?
                .as_str(),
        ),
        PgPrivateCa::from_pem(
            read(&db.ca_file, 1048576, false)
                .map_err(|_| Error::Configuration)?
                .to_vec(),
        )
        .map_err(|_| Error::Configuration)?,
    )
    .with_pool_limits(0, 4);

    PgRuntime::connect_producer(pg, Timer, binding)
        .await
        .map(Arc::new)
        .map_err(|_| Error::Storage)
}
pub fn authority_config(
    i: &Installation,
    integrity: rss_audit_postgres::Integrity,
) -> Result<AuthorityConfig> {
    AuthorityConfig::new(
        InstanceId::parse(&i.instance.to_string()).map_err(|_| Error::Configuration)?,
        i.tenants()?.into_iter().map(|(t, _)| t).collect(),
        SessionPolicy::new(900, 14400).map_err(|_| Error::Configuration)?,
        integrity,
    )
    .map_err(|_| Error::Identity)
}
pub struct Assembly {
    pub browser: axum::Router,
    pub protocol: Arc<http::Services>,
    pub pki: Arc<rss_mdm_pki_service::registry::Registry>,
}
pub async fn assemble(
    config: &Config,
    mut acquire: impl FnMut(Box<DynManagedResource<'static>>),
) -> Result<Assembly> {
    config.validate()?;

    let instance = InstanceId::parse(&config.installation.instance.to_string())
        .map_err(|_| Error::Configuration)?;

    let tenant = rss_request_context::TenantId::parse(&config.installation.tenant.to_string())
        .map_err(|_| Error::Configuration)?;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with(config.database.options()?)
        .await
        .map_err(|_| Error::Storage)?;

    acquire(DynManagedResource::new_box(Pool(pool.clone())));
    // CONNECT is temporarily available to the verifier; incomplete restore never admits a host.
    let restoring: bool =
        sqlx::query_scalar("SELECT to_regclass('public.da_restore_operation') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .map_err(|_| Error::Storage)?;
    if restoring {
        let complete: bool = sqlx::query_scalar("SELECT count(complete)=1 AND coalesce(bool_and(complete),false) FROM public.da_restore_operation")
            .fetch_one(&pool).await.map_err(|_| Error::AdmissionAt("restore state"))?;
        if !complete {
            return Err(Error::Admission);
        }
    }

    let transactions = runtime(&config.database, &config.installation).await?;

    acquire(DynManagedResource::new_box(RuntimeResource(
        transactions.clone(),
    )));

    let identity_runtime = runtime(&config.identity_database, &config.installation).await?;

    acquire(DynManagedResource::new_box(RuntimeResource(
        identity_runtime.clone(),
    )));

    let kdf = Arc::new(PasswordKdf::new());

    acquire(DynManagedResource::new_box(Kdf(kdf.clone())));

    let mut c = pool.acquire().await.map_err(|_| Error::Storage)?;

    da::installation::verify_standalone_access(&mut c, config.audit.ledger())
        .await
        .map_err(|_| Error::AdmissionAt("owner contracts"))?;

    rss_identity_postgres::verify_platform_subject_admission(&mut c, instance)
        .await
        .map_err(|_| Error::AdmissionAt("Identity subject admission"))?;

    let expected = crate::installation::composition(&config.installation, config.audit.ledger())?;

    rss_mdm_install_support::verify_binding(
        &mut c,
        &expected.binding().map_err(|_| Error::Configuration)?,
        &da::installation::standalone_units(config.audit.ledger()),
    )
    .await
    .map_err(|_| Error::AdmissionAt("installation binding"))?;

    use rss_mdm_install_support::Host;

    let receipts = rss_mdm_install_support::read_receipts(&mut c, DA)
        .await
        .map_err(|_| Error::Storage)?;

    expected
        .check_existing(&mut c, &receipts)
        .await
        .map_err(|_| Error::AdmissionAt("installation identity"))?;

    drop(c);

    let audit_budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(10));

    let audit = Arc::new(
        rss_mdm_audit_integration::AuditStore::new(
            pool.clone(),
            config.audit.integrity()?,
            transactions,
            tenant,
            &audit_budget.control(),
        )
        .await
        .map_err(|_| Error::AdmissionAt("Audit runtime"))?,
    );

    let proof_audit = Arc::new(
        audit
            .on_runtime(identity_runtime.clone(), tenant, &audit_budget.control())
            .await
            .map_err(|_| Error::AdmissionAt("Identity Audit"))?,
    );

    let platform = da::Runtime::prepare(&config.browser.origin);

    let mut clients: BTreeMap<
        String,
        Arc<dyn rss_mdm_device_access_postgres::enterprise::broker::Client>,
    > = BTreeMap::new();

    let mut administrators = BTreeMap::new();

    let mut options = authority_config(&config.installation, config.audit.integrity()?)?;

    if let Some(enterprise) = &config.enterprise {
        if enterprise.clients.is_empty()
            || enterprise.clients.len() > 64
            || enterprise.administrators.len() > 64
        {
            return Err(Error::Configuration);
        }
        for c in &enterprise.clients {
            let client =
                da::enterprise::Backend::load(c, tenant).map_err(|_| Error::Configuration)?;

            if clients
                .insert(c.target.id.clone(), Arc::new(client))
                .is_some()
            {
                return Err(Error::Configuration);
            }
        }
        let key =
            read(&enterprise.signing_key_file, 16384, true).map_err(|_| Error::Configuration)?;

        let signer = Arc::new(
            rss_identity_oidc::enterprise::Es256EnterpriseSigner::new(
                enterprise.key_id.clone(),
                &key,
            )
            .map_err(|_| Error::Configuration)?,
        );

        options = options.with_enterprise(
            rss_identity_postgres::platform::EnterpriseConfig::new(
                enterprise
                    .clients
                    .iter()
                    .map(|c| c.target.clone())
                    .collect(),
                signer,
            )
            .map_err(|_| Error::Configuration)?,
        );

        for a in &enterprise.administrators {
            let credential = secret(&a.client_secret_file).map_err(|_| Error::Configuration)?;

            let ca = a
                .private_ca_file
                .as_ref()
                .map(|p| read(p, 65536, false).map_err(|_| Error::Configuration))
                .transpose()?;

            let admin = rss_mdm_device_access_postgres::enterprise::keycloak::Administrator::new(
                a.configuration.clone(),
                credential,
                ca.as_ref().map(|v| v.as_slice()),
            )
            .map_err(|_| Error::Configuration)?;

            if administrators
                .insert(admin.provider, Arc::new(admin))
                .is_some()
            {
                return Err(Error::Configuration);
            }
        }
    }
    let enterprise = Arc::new(
        rss_mdm_device_access_postgres::enterprise::platform::Verifier::new(
            &config.browser.origin,
            tenant,
            identity_runtime.clone(),
            Some(platform.clone()),
            clients
                .iter()
                .map(|(id, c)| (id.clone(), c.fingerprint().to_owned()))
                .collect(),
        ),
    );

    options = options.with_platform(enterprise.clone());

    let policy = Arc::new(
        rss_mdm_authorization_service::identity_management::IdentityManagementPolicy::new(
            DA,
            &instance.to_string(),
        )
        .map_err(|_| Error::Configuration)?,
    );

    let authority = Authority::connect_runtime(identity_runtime, kdf, options, policy, deadline())
        .await
        .map_err(|_| Error::Identity)?;

    let http_config =
        rss_identity_http_axum::HttpConfig::new(&config.browser.origin, Duration::from_secs(10))
            .map_err(|_| Error::Configuration)?;

    let origin = url::Url::parse(&config.browser.origin).map_err(|_| Error::Configuration)?;

    let webauthn = rss_identity_postgres::WebauthnAuthority::connect(
        authority.clone(),
        origin.host_str().ok_or(Error::Configuration)?.to_owned(),
        origin,
        deadline(),
    )
    .await
    .map_err(|_| Error::Identity)?;

    let identity = Arc::new(http::identity::Identity {
        enterprise_clients: clients,
        enterprise_administrators: administrators,
        authority: authority.clone(),
        webauthn: webauthn.clone(),
        http: http_config.clone(),
        tenant,
    });

    let authorization = Arc::new(rss_mdm_authorization_service::Store::from_pool(
        DA,
        pool.clone(),
        Arc::new(Timer),
    ));

    authorization
        .require_management_initializer()
        .await
        .map_err(|_| Error::AdmissionAt("management initializer"))?;

    let protection = config.protection.load()?;

    let cursor = read(&config.cursor_key_file, 64, true).map_err(|_| Error::Configuration)?;

    let cursor =
        rss_mdm_query::cursor::CursorCodec::new(&cursor).map_err(|_| Error::Configuration)?;

    let evidence = Arc::new(
        rss_mdm_device_access_postgres::evidence::Authorities::new(
            config
                .deployment_authorities
                .iter()
                .map(|a| rss_mdm_device_access_postgres::evidence::Authority {
                    id: a.id,
                    public_key: a.public_key,
                })
                .collect(),
        )
        .map_err(|_| Error::Configuration)?,
    );

    let native = config
        .platform_sso
        .as_ref()
        .map(|p| {
            p.load(&config.browser.origin, tenant, &evidence)
                .map_err(|_| Error::Configuration)
        })
        .transpose()?;

    let r = &config.registration;

    let trust = rss_mdm_pki_service::configuration::load(
        &r.trust_file,
        rss_mdm_agent_wire::pki::Purpose::DaDevice,
        now(),
    )
    .map_err(|_| Error::Configuration)?;

    let public = trust.public().map_err(|_| Error::Configuration)?;

    if public.origin != r.listener.origin
        || public.tenant.to_string() != tenant.to_string()
        || public.service_id.to_string() != instance.to_string()
    {
        return Err(Error::Configuration);
    }
    let providers = rss_mdm_pki_service::configuration::providers(&r.providers)
        .map_err(|_| Error::Configuration)?;

    let pki = Arc::new(rss_mdm_pki_service::registry::Registry::new(
        DA,
        pool.clone(),
        audit.clone(),
        vec![trust.clone()],
        providers.clone(),
    ));

    pki.admit(tenant, now())
        .await
        .map_err(|_| Error::AdmissionAt("PKI registry"))?;

    let trust = Arc::new(
        rss_mdm_device_trust::device_identity::DeviceIdentityTrust::from_trust(
            trust,
            r.certificate_days,
        )
        .map_err(|_| Error::Configuration)?,
    );

    let issuer = Arc::new(
        rss_mdm_registration_service::certificate_issuance::DeviceIssuer::new(
            DA,
            providers,
            r.certificate_days,
            false,
            trust,
            Arc::new(Timer),
        )
        .map_err(|_| Error::Configuration)?,
    );

    let loaded = if let Some(revision) = r.configuration_revision {
        let mut tx = pool.begin().await.map_err(|_| Error::Storage)?;

        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;

        let loaded = rss_mdm_task_trust::trust::load(
            DA,
            rss_mdm_task_trust::Use::DaConfiguration,
            &mut tx,
            tenant,
            revision,
            &protection,
        )
        .await
        .map_err(|_| Error::AdmissionAt("configuration signing trust"))?;

        tx.rollback().await.map_err(|_| Error::Storage)?;

        Some(loaded)
    } else {
        None
    };

    let inputs = da::Registration {
        issuer,
        clock: Arc::new(Timer),
        signing: Arc::new(
            rss_mdm_task_trust::Signing::new(
                DA,
                rss_mdm_task_trust::Use::DaConfiguration,
                tenant,
                loaded,
            )
            .map_err(|_| Error::Configuration)?,
        ),
        configuration_lifetime: r.configuration_lifetime,
    };

    let runtime = da::Runtime::assemble(
        da::Resources {
            report_limits: config.reports.clone(),
            tenant,
            installation: config.installation.instance,
            identity_instance: instance,
            pool: pool.clone(),
            audit: audit.clone(),
            proof_audit: proof_audit.clone(),
            cursor: cursor.clone(),
            protection,
            platform: native,
            evidence: evidence.clone(),
            broker_query: None,
            agent_facts: None,
        },
        Some(inputs),
    )
    .map_err(|_| Error::AdmissionAt("DA runtime"))?;

    runtime
        .bind(&platform, &enterprise)
        .map_err(|_| Error::AdmissionAt("Identity provider binding"))?;

    let recovery = config
        .recovery
        .as_ref()
        .map(|r| r.open().map_err(|_| Error::Configuration))
        .transpose()?
        .map(|p| {
            Arc::new(rss_mdm_recovery_credentials::Credentials::new(
                DA,
                pool,
                audit.clone(),
                p.keys.clone(),
                Some(proof_audit),
                Some(Arc::new(
                    rss_mdm_device_access_postgres::recovery::eligibility::AccessEligibility {
                        admission: Some(runtime.admission.clone()),
                    },
                )),
            ))
        });

    let platform_http = Arc::new(http::platform_sso::HttpState {
        context: runtime.platform.clone(),
        authority: authority.clone(),
        origin: config.browser.origin.clone(),
    });

    let business = Arc::new(http::device_access::Services {
        cursor: cursor.clone(),
        recovery,
        registration: runtime.business.clone(),
        admission: runtime.admission.clone(),
        identity: identity.clone(),
    });

    let state = Arc::new(http::browser::Services {
        pki: Arc::new(http::pki::HttpState {
            registry: pki.clone(),
            cursor: cursor.clone(),
            clock: Arc::new(Timer),
        }),
        identity,
        authorization: authorization.clone(),
        audit: audit.clone(),
        business,
        platform: platform_http.clone(),
        origin: config.browser.origin.clone(),
        host: config.browser.host()?,
        platform_configuration: serde_json::json!({"authorities":evidence.fingerprints()}),
        requests: Arc::new(tokio::sync::Semaphore::new(32)),
    });

    let mut identity_routes =
        rss_identity_http_axum::router(authority.clone(), http_config.clone())
            .map_err(|_| Error::Identity)?
            .merge(
                rss_identity_http_axum::webauthn_router(webauthn, http_config.clone())
                    .map_err(|_| Error::Identity)?,
            )
            .merge(
                rss_identity_http_axum::bearer_router(authority.clone(), http_config.clone())
                    .map_err(|_| Error::Identity)?,
            );

    if let Some(oidc) = &config.oidc {
        identity_routes = identity_routes.merge(
            rss_identity_http_axum::federated_router(
                oidc.federation(authority.clone(), &config.browser.origin, instance)?,
                http_config,
            )
            .map_err(|_| Error::Identity)?,
        );
    }
    let browser = http::browser::router(Some(&state))
        .into_checked_axum(rss_mdm_http_contract::module::Listener::Browser)
        .merge(identity_routes);

    let browser_requests = state.requests.clone();

    let browser = http::browser::envelope(browser, state);

    let protocol = Arc::new(http::Services {
        business: Some(Arc::new(http::Business {
            evidence,
            service: runtime.business,
            admission: runtime.admission,
            platform: platform_http,
        })),
        registrations: runtime.registrations.ok_or(Error::Admission)?,
        configurations: runtime.configurations.ok_or(Error::Admission)?,
        authorization,
        sessions: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(authority, tenant),
        ),
        audit,
        host: r.listener.host()?,
        requests: Arc::new(tokio::sync::Semaphore::new(16)),
    });

    acquire(DynManagedResource::new_box(Requests([
        browser_requests,
        protocol.requests.clone(),
    ])));

    Ok(Assembly {
        browser,
        protocol,
        pki,
    })
}
fn certificates(
    input: &Listener,
) -> Result<(
    Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let chain = CertificateDer::pem_slice_iter(
        &read(&input.certificate_file, 131072, false).map_err(|_| Error::Configuration)?,
    )
    .collect::<std::result::Result<Vec<_>, _>>()
    .map_err(|_| Error::Configuration)?;

    let key = PrivateKeyDer::from_pem_slice(
        &read(&input.private_key_file, 32768, true).map_err(|_| Error::Configuration)?,
    )
    .map_err(|_| Error::Configuration)?;

    Ok((chain, key))
}
pub(crate) fn validate_tls(config: &Config) -> Result<()> {
    for listener in [&config.browser, &config.registration.listener] {
        let (chain, key) = certificates(listener)?;
        tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|_| Error::Configuration)?;
    }
    Ok(())
}
fn http_policy() -> Result<rss_axum::Http1ServePolicy> {
    rss_axum::Http1ServePolicy::new(
        rss_axum::ServePolicy::new(
            32,
            Duration::from_secs(5),
            Duration::from_secs(3),
            Duration::from_secs(15),
        )
        .map_err(|_| Error::Configuration)?,
        Duration::from_secs(3),
        64,
        32768,
    )
    .map_err(|_| Error::Configuration)
}
pub async fn serve(
    config: Config,
    stop: impl std::future::Future<Output = std::io::Result<()>>,
) -> Result<()> {
    config.validate()?;

    let mut scope = LifecycleScope::<(), Error, std::io::Error>::try_new(
        TotalDrainBudget::new(Duration::from_secs(45)).map_err(|_| Error::Lifecycle)?,
        Arc::new(Timer),
    )
    .map_err(|_| Error::Lifecycle)?;

    let outcome=scope.drive(|mut startup| {Box::pin(async move {
  let app=tokio::time::timeout(Duration::from_secs(60),assemble(&config,|r|startup.stage_resource(r))).await.map_err(|_|Error::Lifecycle)??;

  let (chain,key)=certificates(&config.browser)?;

  let tcp=tokio::net::TcpListener::bind(config.browser.listen).await.map_err(|_|Error::Lifecycle)?;

  let listener=http::tls::browser(tcp,chain,key,app.browser,http_policy()?).map_err(|_|Error::Lifecycle)?;

  startup.stage_task_with_token(listener.critical());

  let (chain,key)=certificates(&config.registration.listener)?;

  let tcp=tokio::net::TcpListener::bind(config.registration.listener.listen).await.map_err(|_|Error::Lifecycle)?;

  startup.stage_task_with_token(http::tls::registration(tcp,chain,key,app.protocol,http_policy()?).map_err(|_|Error::Lifecycle)?.critical());

  let (task,_)=rss_runtime::ManagedTask::prepare("da-pki-maintenance",Duration::from_secs(10));

  startup.stage_task_with_token(task.into_registration(move|stop|async move{loop{tokio::select!{biased;
()=stop.cancelled()=>return Ok(()),result=app.pki.sweep(||Ok(now()))=>{if result.is_err(){eprintln!("da_pki_maintenance_unavailable");
}}}tokio::select!{biased;
()=stop.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_secs(60))=>{}}}}));

  let launch=startup.commit();

  launch.finish();

  std::future::pending().await
 })},stop).await.map_err(|_|Error::Lifecycle)?;

    let clean = outcome.shutdown().as_ref().is_ok_and(|r| r.is_clean());

    match outcome.exit() {
        ScopeExit::Completed(Err(error)) => Err(error.clone()),
        ScopeExit::StopRequested(Ok(())) if clean => Ok(()),
        _ => Err(Error::Lifecycle),
    }
}
