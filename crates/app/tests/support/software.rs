//! Real HTTP preparation for content and software adapters; no behavior matrix runs here.
use super::{http::*, runtime::*, *};
use uuid::Uuid;
// Only fixture preparation is serialized; business contention tests use the API directly.
// The file belongs to the shared content environment and coordinates separate test processes.
pub(crate) async fn content_setup_guard() -> Result<std::fs::File> {
    let config: Value = serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
    let directory =
        std::path::PathBuf::from(config["content"]["storage"]["directory"].as_str().unwrap());
    tokio::task::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join(".t2-content-setup.lock"))?;
        file.lock()?;
        Ok(file)
    })
    .await?
}
pub(crate) struct HttpServer(tokio::task::JoinHandle<std::io::Result<()>>);
impl HttpServer {
    pub(crate) fn start(listener: tokio::net::TcpListener, router: Router) -> Self {
        Self(tokio::spawn(
            async move { axum::serve(listener, router).await },
        ))
    }
}
impl Drop for HttpServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) struct Fixture {
    pub(crate) resources: super::runtime::Resources,
    pub(crate) directory: std::path::PathBuf,
    pub(crate) router: Router,
    pub(crate) content: Option<Arc<rss_mdm_content_service::Store>>,
    pub(crate) runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) user: Browser,
    pub(crate) client: Client,
    pub(crate) origin: String,
    pub(crate) subject: String,
    pub(crate) registered: Value,
    pub(crate) peer: Option<publication_support::Server>,
    pub(crate) server: HttpServer,
    pub(crate) software: Arc<
        rss_mdm_software_service::management::catalog::Access<
            rss_mdm_content_service::software::SoftwareContent,
        >,
    >,
}
impl Fixture {
    pub(crate) async fn open(mirror: bool) -> Result<Self> {
        let peer = if mirror {
            Some(publication_support::Server::new().await)
        } else {
            None
        };
        Self::with_peer(peer).await
    }
    pub(crate) async fn with_peer(peer: Option<publication_support::Server>) -> Result<Self> {
        Self::with_peer_and_uploads(peer, None).await
    }
    pub(crate) async fn with_peer_and_uploads(
        peer: Option<publication_support::Server>,
        max_uploads: Option<u64>,
    ) -> Result<Self> {
        Self::with_storage_and_options(peer, max_uploads, None, None).await
    }
    pub(crate) async fn with_storage(storage: Value) -> Result<Self> {
        Self::with_storage_and_options(None, None, Some(storage), None).await
    }
    pub(crate) async fn with_transfer_seconds(seconds: u64) -> Result<Self> {
        Self::with_storage_and_options(None, None, None, Some(seconds)).await
    }
    async fn with_storage_and_options(
        peer: Option<publication_support::Server>,
        max_uploads: Option<u64>,
        storage: Option<Value>,
        transfer_seconds: Option<u64>,
    ) -> Result<Self> {
        let (resources, mut fixture) = crate::test_support::runtime::Resources::build(move |resources| Box::pin(async move {
        let mut base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        let directory =
            std::path::PathBuf::from(base["content"]["storage"]["directory"].as_str().unwrap());
        if let Some(seconds) = transfer_seconds {
            base["content"]["transfer_seconds"] = json!(seconds);
            base["content"]["max_artifact_bytes"] = json!(160 * 1024 * 1024);
            base["content"]["max_temporary_bytes"] = json!(512 * 1024 * 1024);
        }
        if let Some(storage) = storage {
            base["content"]["storage"] = storage;
            base["content"]["max_artifact_bytes"] = json!(160 * 1024 * 1024);
            base["content"]["max_temporary_bytes"] = json!(512 * 1024 * 1024);
        }
        if let Some(max_uploads) = max_uploads {
            base["content"]["max_uploads"] = json!(max_uploads);
        }

        if let Some(peer) = &peer {
            base["content"]["imports"][&peer.logical] = json!([{"base":format!("{}artifacts/",peer.base),"addresses":[peer.address],"private_ca":peer.ca}]);
            if peer.state.lock().unwrap().import_manifest.is_some() {
                base["content"]["imports"][format!("{}-import", peer.logical)] = json!([{"base":format!("{}import/",peer.base),"addresses":[peer.address],"private_ca":peer.ca}]);
            }
        }
        crate::test_support::storage::seed(&serde_json::from_value(base.clone())?).await?;
        let config: Config = serde_json::from_value(base.clone())?;
        let mut authority = authority::Authority::from_config(base.clone()).await?;
        resources.extend(std::mem::take(&mut authority.resources));
        let tenant = authority.identity.tenant;
        let runtime = crate::planning::test_support::runtime(tenant).await;
        resources.resource(SourceResource(runtime.clone()));
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let audit = Arc::new(authority.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
        let clock = Arc::new(crate::clock::SystemClock);
        let content = crate::execution_assembly::open_content(&config, config.native_protector()?).await?;
        if let Some(store) = &content { resources.resource(crate::execution_assembly::ContentResource(store.clone())); }
        let reader = Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant));
        let content_access = Arc::new(rss_mdm_content_service::service::Access {
            sessions: rss_mdm_authorization_service::session::SessionAuthority::new(authority.identity.authority.clone(), tenant),
            authorization: authority.authorization.clone(), runtime: runtime.clone(),
            audit_store: audit.clone(), tenant, content: content.clone(),
            clock: Arc::new(crate::clock::ContentClock(clock.clone())), catalog: reader,
        });
        let resources_store = Arc::new(rss_mdm_resource_postgres::ResourceStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?);
        let key = rss_mdm_flow_service::storage::cursor_key(&runtime, tenant).await?;
        let software = Arc::new(rss_mdm_software_service::management::catalog::Access {
            runtime: runtime.clone(), cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key)),
            audit: audit.clone(), tenant,
            catalog: rss_mdm_software_service::catalog::Catalog::new(runtime.clone(), tenant, audit.clone()),
            resources: resources_store, clock: Arc::new(crate::clock::ContentClock(clock.clone())),
            content: content.as_ref().map(|store| Arc::new(rss_mdm_content_service::software::SoftwareContent::new(store.clone(), Arc::new(crate::clock::ContentClock(clock.clone()))))),
            imports: rss_mdm_software_service::management::catalog::ImportConfig {
                sources: content.as_ref().map(|store| store.config.imports.clone()).unwrap_or_default(),
                transfer_seconds: content.as_ref().map_or(0, |store| store.config.transfer_seconds),
            },
        });
        let catalog = crate::flow::catalog(audit.clone(), runtime.clone(), tenant, clock).await?;
        let router = authority.router(rss_mdm_http_contract::Router::new().nest("/api/v1",
            rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(
                rss_mdm_management_http::resource_catalog::http::HttpState { catalog, content: content_access.clone() },
            ))
            .merge(rss_mdm_management_http::software_catalog::routes().with_state(software.clone()))
            .merge(rss_mdm_management_http::content::http::routes().with_state(content_access)),
        ).merge(authority.authorization()))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let hosted = router.clone();
        let server = HttpServer(tokio::spawn(
            async move { axum::serve(listener, hosted).await },
        ));
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let origin = format!("http://{address}");
        let user = Browser {
            network: Some((client.clone(), origin.clone())),
            ..authority::Authority::prepared_browser("admin")?
        };
        let subject = prepared_subject(&user)?;
        let grants = [
            "resource_read",
            "resource_write",
            "software_read",
            "software_write",
            "software_withdraw",
        ]
        .into_iter()
        .map(|s| {
            Ok(crate::authorization::Grant {
                operation: serde_json::from_value(json!(s))?,
                scope: crate::authorization::Scope::Tenant,
            })
        })
        .collect::<Result<Vec<_>>>()?;
        crate::test_support::identity::seed_grants(case_tenant(), &subject, grants).await?;
        let source = peer.as_ref().map_or_else(
            || case::name("private-fixture").to_owned(),
            |peer| peer.logical.clone(),
        );
        let definition = rss_mdm_software_service::catalog::SourceDefinition {
            id: source, revision: "1".into(), protocol: rss_mdm_software_service::catalog::SourceProtocol::Private,
        };
        let snapshot = runtime.local_tx(tenant, crate::identity::deadline(), move |tx| Box::pin(async move {
            rss_mdm_software_service::catalog::fixture::source_in(tx, definition).await.map_err(|error| rss_transactional_messaging_postgres::PgError::from(sqlx::Error::Protocol(error.to_string())))
        })).await.fold(Ok, |e| Err(anyhow::anyhow!(e)), |e| Err(anyhow::anyhow!(e)), |_| Err(anyhow::anyhow!("source seed rollback unconfirmed")), |_| Err(anyhow::anyhow!("source seed commit unconfirmed")), |e| Err(anyhow::anyhow!(e)))?;
        let registered = json!({"snapshot":snapshot});
        Ok(Self {
            resources: Default::default(),
            directory,
            router,
            content,
            runtime,
            user,
            client,
            origin,
            subject,
            registered,
            peer,
            server,
            software,
        })

        })).await?;
        fixture.resources = resources;
        Ok(fixture)
    }
}
pub(crate) async fn write(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    input: Value,
) -> Result<Value> {
    let expected = if input["action"] == "publish" {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    let body = json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input});
    let response = browser.call(router, Method::POST, path, Some(body)).await?;
    ensure!(response.0 == expected, "{path}: {response:?}");
    Ok(response.1)
}

pub(crate) async fn seed_software_version(
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    mut definition: Value,
) -> Result<(String, Value)> {
    use rss_mdm_resource::{Architecture, Declaration, Id, Kind, Platform, Variant, Version};
    let resource = Uuid::new_v4().to_string();
    definition["package"] = json!(format!("Private.{resource}"));
    let tenant = rss_request_context::TenantId::parse(case_tenant())?;
    let version = Version::new(
        tenant,
        Id::new(resource.clone())?,
        Id::new("v1")?,
        Kind::Software,
        vec![Variant::new(
            Platform::Windows,
            Architecture::X86_64,
            Id::new("default")?,
            Declaration::Software {
                definition: serde_json::from_value(definition)?,
            },
        )],
    )?;
    let digest = json!(version.digest().bytes());
    runtime
        .local_tx(tenant, crate::identity::deadline(), move |tx| {
            Box::pin(async move {
                rss_mdm_resource_postgres::fixture::active_version_in(
                    tx,
                    version,
                    rss_contract::Timepoint::try_from(1_i64).expect("fixture time"),
                )
                .await
            })
        })
        .await
        .fold(
            Ok,
            |e| Err(anyhow::anyhow!(e)),
            |e| Err(anyhow::anyhow!(e)),
            |_| Err(anyhow::anyhow!("resource rollback unconfirmed")),
            |_| Err(anyhow::anyhow!("resource commit unconfirmed")),
            |e| Err(anyhow::anyhow!(e)),
        )?;
    Ok((resource, digest))
}

impl Fixture {
    pub(crate) async fn seed_content(&self, bytes: &[u8]) -> Result<rss_mdm_resource::Artifact> {
        let _guard = content_setup_guard().await?;
        let definition =
            publication_support::private_definition(self.registered["snapshot"].clone(), bytes);
        let source = serde_json::from_value(definition["source"].clone())?;
        let inspection = serde_json::from_value(definition["material"]["format"].clone())?;
        let (id, digest) = seed_software_version(&self.runtime, definition).await?;
        let store = self
            .content
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("content store missing"))?;
        let artifact = rss_mdm_resource::Artifact::new(
            rss_mdm_resource::Id::new("installer")?,
            bytes.len() as u64,
            rss_mdm_resource::Digest::of(bytes),
        )?;
        let binding = rss_mdm_content_service::Binding {
            purpose: rss_mdm_content_service::Purpose::Resource(
                rss_mdm_content_service::ResourceBinding {
                    inspection: Some(inspection),
                    storage_class: rss_mdm_content_service::StorageClass::Artifact,
                    resource: id,
                    version: "v1".into(),
                    variant: "default".into(),
                    platform: rss_mdm_resource::Platform::Windows,
                    architecture: rss_mdm_resource::Architecture::X86_64,
                    resource_digest: serde_json::from_value(digest)?,
                    source: Some(source),
                    origin: None,
                },
            ),
            reference: artifact.reference().as_str().into(),
            length: artifact.length(),
            sha256: artifact.digest().bytes(),
            actor: self.subject.clone(),
        };
        let operation = Uuid::new_v4();
        let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        rss_mdm_content_service::fixture::artifact(store, &artifact, bytes.to_vec(), now + 86400)
            .await?;
        let upload = rss_mdm_content_service::Upload {
            id: operation,
            binding,
            offset: bytes.len() as u64,
            expires: now + 86400,
            complete: true,
        };
        self.runtime
            .local_tx(
                rss_request_context::TenantId::parse(case_tenant())?,
                crate::identity::deadline(),
                move |tx| {
                    Box::pin(async move {
                        rss_mdm_content_service::bindings::bind_in(tx, &upload)
                            .await
                            .map_err(|e| {
                                rss_transactional_messaging_postgres::PgError::from(
                                    sqlx::Error::Protocol(e.to_string()),
                                )
                            })
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(anyhow::anyhow!(e)),
                |e| Err(anyhow::anyhow!(e)),
                |_| Err(anyhow::anyhow!("content preparation rollback unconfirmed")),
                |_| Err(anyhow::anyhow!("content preparation commit unconfirmed")),
                |e| Err(anyhow::anyhow!(e)),
            )?;
        Ok(artifact)
    }
}
