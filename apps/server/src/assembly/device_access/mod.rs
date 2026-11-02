//! Current application's DA subassembly. Resource lifetimes belong to the host.
pub(crate) mod config;
use crate::{ConfigIssue, Error, Failure};
use rss_mdm_install_support::StorageProfile;
use std::{sync::Arc, time::Duration};
pub struct Assembly {
    pub runtime: rss_mdm_device_access_runtime::Runtime,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub pki: Option<Arc<rss_mdm_pki_service::registry::Registry>>,
    pub recovery: Option<Arc<rss_mdm_recovery_credentials::Credentials>>,
}
fn invalid() -> Error {
    Error::Configuration(ConfigIssue::DeviceAccess)
}
struct Pool(sqlx::PgPool);
impl rss_runtime::ManagedResource for Pool {
    fn name(&self) -> &str {
        "da-access-postgres"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.0.close().await;
        Ok(())
    }
}
struct Clock;
impl rss_mdm_registration_service::certificate_issuance::Clock for Clock {
    fn unix_seconds(&self) -> Result<i64, rss_mdm_registration_service::Error> {
        use crate::clock::Clock;
        crate::clock::SystemClock
            .unix_seconds()
            .map_err(|_| rss_mdm_registration_service::Error::Storage)
    }
}
pub(crate) async fn open(
    config: &crate::config::Config,
    identity: &crate::identity::Identity,
    authorization: &rss_mdm_authorization_service::Store,
    protection: Arc<rss_mdm_native_protection::Protector>,
    cursor: &[u8],
    mut acquire: impl FnMut(Box<rss_runtime::DynManagedResource<'static>>),
) -> Result<Assembly, Error> {
    let d = &config.device_access;
    if d.database.user != "da_access"
        || d.database.host != config.access_database.host
        || d.database.port != config.access_database.port
        || d.database.name != config.access_database.name
    {
        return Err(invalid());
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with(d.database.options()?)
        .await
        .map_err(crate::database::db)?;
    acquire(rss_runtime::DynManagedResource::new_box(Pool(pool.clone())));
    let runtime = crate::identity::open_runtime(
        &d.database,
        &config.storage_binding.target,
        &config.storage_binding.lineage,
        &[(identity.tenant, config.storage_binding.epoch)],
        4,
    )
    .await?;
    acquire(rss_runtime::DynManagedResource::new_box(
        crate::owner_storage::Resource::new(runtime.clone(), "da-transactions-postgres"),
    ));
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(10));
    let audit = Arc::new(
        rss_mdm_audit_integration::AuditStore::new(
            pool.clone(),
            config.audit.integrity()?,
            runtime,
            identity.tenant,
            &budget.control(),
        )
        .await?,
    );
    let mut c = pool.acquire().await.map_err(crate::database::db)?;
    super::super::migration::device_access::verify_runtime(&mut c)
        .await
        .map_err(crate::database::db)?;
    crate::migration::device_access::verify_access(&mut c, &config.audit)
        .await
        .map_err(crate::database::db)?;
    drop(c);
    let evidence = Arc::new(
        rss_mdm_device_access_postgres::evidence::Authorities::new(
            d.deployment_authorities
                .iter()
                .map(|a| rss_mdm_device_access_postgres::evidence::Authority {
                    id: a.id,
                    public_key: a.public_key,
                })
                .collect(),
        )
        .map_err(|_| invalid())?,
    );
    let platform = d
        .platform_sso
        .as_ref()
        .map(|p| p.load(&config.product_origin, identity.tenant, &evidence))
        .transpose()?;
    let mut pki = None;
    let inputs = if let Some(r) = &d.registration {
        use crate::clock::Clock as _;
        let now = crate::clock::SystemClock.unix_seconds()?;
        if r.providers.is_empty()
            || r.providers
                .iter()
                .any(|p| p.purpose != rss_mdm_agent_wire::pki::Purpose::DaDevice)
        {
            return Err(invalid());
        }
        let trust = crate::device_pki::load(
            &r.trust_file,
            rss_mdm_agent_wire::pki::Purpose::DaDevice,
            now,
        )?;
        let public = trust.public().map_err(|_| invalid())?;
        if public.origin != r.origin
            || public.tenant.to_string() != identity.tenant.to_string()
            || public.service_id.to_string() != identity.instance.to_string()
        {
            return Err(invalid());
        }
        let providers = crate::device_pki::providers(&r.providers)?;
        let registry = Arc::new(rss_mdm_pki_service::registry::Registry::new(
            StorageProfile::Da,
            pool.clone(),
            audit.clone(),
            vec![trust.clone()],
            providers.clone(),
        ));
        registry
            .admit(identity.tenant, now)
            .await
            .map_err(|_| invalid())?;
        pki = Some(registry);
        let trust = Arc::new(
            rss_mdm_device_trust::device_identity::DeviceIdentityTrust::from_trust(
                trust,
                r.certificate_days,
            )
            .map_err(|_| invalid())?,
        );
        let issuer = Arc::new(
            rss_mdm_registration_service::certificate_issuance::DeviceIssuer::new(
                StorageProfile::Da,
                providers,
                r.certificate_days,
                false,
                trust,
                Arc::new(Clock),
            )
            .map_err(|_| invalid())?,
        );
        let loaded = if let Some(revision) = r.configuration_revision {
            let mut tx = pool.begin().await.map_err(crate::database::db)?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(identity.tenant.to_string())
                .execute(&mut *tx)
                .await
                .map_err(crate::database::db)?;
            let loaded = rss_mdm_task_trust::trust::load(
                StorageProfile::Da,
                rss_mdm_task_trust::Use::DaConfiguration,
                &mut tx,
                identity.tenant,
                revision,
                &protection,
            )
            .await
            .map_err(|_| invalid())?;
            tx.rollback().await.map_err(crate::database::db)?;
            Some(loaded)
        } else {
            None
        };
        Some(rss_mdm_device_access_runtime::Registration {
            issuer,
            clock: Arc::new(Clock),
            signing: Arc::new(
                rss_mdm_task_trust::Signing::new(
                    StorageProfile::Da,
                    rss_mdm_task_trust::Use::DaConfiguration,
                    identity.tenant,
                    loaded,
                )
                .map_err(|_| invalid())?,
            ),
            configuration_lifetime: r.configuration_lifetime,
        })
    } else {
        None
    };
    let proof_audit = Arc::new(
        audit
            .on_runtime(identity.runtime.clone(), identity.tenant, &budget.control())
            .await?,
    );
    let business = rss_mdm_device_access_runtime::Runtime::assemble(
        rss_mdm_device_access_runtime::Resources {
            report_limits: d.reports.clone(),
            tenant: identity.tenant,
            installation: uuid::Uuid::parse_str(&identity.instance.to_string())
                .map_err(|_| invalid())?,
            identity_instance: identity.instance,
            pool: pool.clone(),
            audit: audit.clone(),
            proof_audit: proof_audit.clone(),
            cursor: rss_mdm_query::cursor::CursorCodec::new(cursor).map_err(|_| invalid())?,
            protection,
            platform,
            evidence,
            broker_query: Some(rss_mdm_agent_channel::enrollment_facts::DA_BROKER_QUERY),
            agent_facts: Some(Arc::new(super::registration_agent_facts::AgentFacts::new(
                StorageProfile::Mdm,
            ))),
        },
        inputs,
    )
    .map_err(|_| invalid())?;
    let authorization = Arc::new(authorization.for_product(StorageProfile::Da));
    let recovery = config
        .recovery_credentials
        .as_ref()
        .map(crate::recovery_credentials::Config::open)
        .transpose()?
        .map(|p| {
            Arc::new(rss_mdm_recovery_credentials::Credentials::new(
                StorageProfile::Da,
                pool.clone(),
                audit.clone(),
                p.keys.clone(),
                Some(proof_audit),
                Some(Arc::new(
                    rss_mdm_device_access_postgres::recovery::eligibility::AccessEligibility {
                        admission: Some(business.admission.clone()),
                    },
                )),
            ))
        });
    Ok(Assembly {
        runtime: business,
        authorization,
        audit,
        recovery,
        pki,
    })
}
/// Product composition retains platform-session rechecks even when enrollment is disabled.
pub(crate) async fn identity_platform(
    config: &crate::config::Config,
) -> Result<Arc<rss_mdm_device_access_postgres::platform_sso::bridge::Verifier>, Error> {
    use sqlx::Connection;
    let invalid = || Error::Configuration(ConfigIssue::DeviceAccess);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut connection = sqlx::PgConnection::connect_with(&config.identity.database.options()?)
            .await
            .map_err(|_| invalid())?;
        let result =
            rss_mdm_device_access_postgres::platform_sso::verify_runtime(&mut connection).await;
        connection.close().await.map_err(|_| invalid())?;
        result.map_err(|_| invalid())
    })
    .await
    .map_err(|_| invalid())??;
    Ok(Arc::new(
        rss_mdm_device_access_postgres::platform_sso::bridge::Verifier::new(&config.product_origin),
    ))
}

pub(crate) fn browser(
    runtime: Option<(
        &Arc<super::Assembly>,
        &rss_mdm_management_http::boundary::Envelope,
    )>,
) -> rss_mdm_http_contract::Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    use rss_mdm_device_access_http as http;
    let state = runtime.map(|(s, _)| s);
    let psso = state.map(|s| {
        Arc::new(http::platform_sso::HttpState {
            context: s.da.runtime.platform.clone(),
            authority: s.identity.authority.clone(),
            origin: format!("https://{}", runtime.unwrap().1.host),
        })
    });
    let business = state.map(|s| {
        Arc::new(http::device_access::Services {
            cursor: rss_mdm_query::cursor::CursorCodec::new(&s.cursor_key)
                .expect("admitted cursor"),
            recovery: s.da.recovery.clone(),
            registration: s.da.runtime.business.clone(),
            admission: s.da.runtime.admission.clone(),
            identity: s.identity.da_browser(),
        })
    });
    let access = http::device_access::mount(business.clone(), true);
    let administration = http::administration::routes().bind_with(business.as_ref(), Arc::clone);
    let authentication = state.map(|s| {
        Arc::new(
            rss_mdm_management_http::authorization::http::AuthenticationState {
                identity: s.identity.browser(),
                access: s.da.authorization.clone(),
                requests: s.requests.clone(),
            },
        )
    });
    rss_mdm_http_contract::route_module! {struct DaManagement for [Browser]{access [optional],administration}}
    let access = DaManagement {
        access,
        administration,
    }
    .assemble();
    rss_mdm_http_contract::route_module! {struct DaProtected for [Browser]{access at "/api/v1",platform}}
    let protected = DaProtected {
        access,
        platform: http::platform_sso::management_routes().bind_with(psso.as_ref(), Arc::clone),
    }
    .assemble();
    let protected = rss_mdm_management_http::authorization::http::mount_protection(
        protected,
        authentication,
        false,
    );
    rss_mdm_http_contract::route_module! {struct DaBrowser for [Browser]{protected,broker [optional],browser}}
    let router=DaBrowser{protected,broker:http::enterprise_broker::mount(state.map(|s|Arc::new(http::enterprise_broker::Services{registration:s.da.runtime.business.clone(),admission:s.da.runtime.admission.clone(),identity:s.identity.da_browser(),origin:format!("https://{}",runtime.unwrap().1.host),platform_configuration:match &s.platform_configuration {Some(c)=>serde_json::to_value(c).expect("closed configuration"),None=>serde_json::json!({"authorities":s.da.runtime.admission.evidence.fingerprints()})}})),true),browser:http::platform_sso::browser_routes().bind_with(psso.as_ref(),Arc::clone)}.assemble();
    if let Some((s, envelope)) = runtime {
        rss_mdm_management_http::boundary::wrap(
            router,
            rss_mdm_management_http::boundary::Envelope {
                profile: StorageProfile::Da,
                audit_store: s.da.audit.clone(),
                ..envelope.clone()
            },
        )
    } else {
        router
    }
}

pub(crate) async fn listener(
    config: &crate::config::Config,
    identity: &crate::identity::Identity,
    assembly: &Assembly,
) -> Result<Option<rss_runtime::ManagedTaskRegistration>, Error> {
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let Some(input) = &config.device_access.registration else {
        return Ok(None);
    };
    let origin = crate::config::https_url(&input.origin).map_err(|_| invalid())?;
    if origin.origin().ascii_serialization() != input.origin || input.listen.port() == 0 {
        return Err(invalid());
    }
    let host = input
        .origin
        .strip_prefix("https://")
        .ok_or_else(invalid)?
        .to_owned();
    let certificates = CertificateDer::pem_file_iter(&input.certificate_file)
        .map_err(|_| invalid())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    let key = PrivateKeyDer::from_pem_file(&input.private_key_file).map_err(|_| invalid())?;
    let services = Arc::new(rss_mdm_device_access_http::Services {
        business: Some(Arc::new(rss_mdm_device_access_http::Business {
            evidence: assembly.runtime.admission.evidence.clone(),
            service: assembly.runtime.business.clone(),
            admission: assembly.runtime.admission.clone(),
            platform: Arc::new(rss_mdm_device_access_http::platform_sso::HttpState {
                context: assembly.runtime.platform.clone(),
                authority: identity.authority.clone(),
                origin: config.product_origin.clone(),
            }),
        })),
        registrations: assembly.runtime.registrations.clone().ok_or_else(invalid)?,
        configurations: assembly
            .runtime
            .configurations
            .clone()
            .ok_or_else(invalid)?,
        authorization: assembly.authorization.clone(),
        sessions: Arc::new(
            rss_mdm_authorization_service::session::SessionAuthority::new(
                identity.authority.clone(),
                identity.tenant,
            ),
        ),
        audit: assembly.audit.clone(),
        host,
        requests: Arc::new(tokio::sync::Semaphore::new(16)),
    });
    let tcp = tokio::net::TcpListener::bind(input.listen)
        .await
        .map_err(|_| Error::Unavailable(Failure::Runtime))?;
    let policy = rss_axum::Http1ServePolicy::new(
        rss_axum::ServePolicy::new(
            16,
            Duration::from_secs(5),
            Duration::from_secs(3),
            Duration::from_secs(12),
        )
        .map_err(|_| invalid())?,
        Duration::from_secs(3),
        64,
        32768,
    )
    .map_err(|_| invalid())?;
    rss_mdm_device_access_http::tls::registration(tcp, certificates, key, services, policy)
        .map(Some)
        .map_err(|_| invalid())
}
