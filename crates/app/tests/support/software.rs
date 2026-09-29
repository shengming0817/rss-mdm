//! Real HTTP preparation for content and software adapters; no behavior matrix runs here.
use super::*;
use uuid::Uuid;
pub(crate) struct HttpServer(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for HttpServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) struct Fixture {
    pub(crate) directory: std::path::PathBuf,
    pub(crate) router: Router,
    pub(crate) execution: Arc<crate::execution::ExecutionService>,
    pub(crate) runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub(crate) user: Browser,
    pub(crate) client: Client,
    pub(crate) origin: String,
    pub(crate) subject: String,
    pub(crate) registered: Value,
    pub(crate) peer: Option<publication_support::Server>,
    _server: HttpServer,
}
impl Fixture {
    pub(crate) async fn open(mirror: bool) -> Result<Self> {
        let peer = if mirror {
            Some(publication_support::Server::new().await)
        } else {
            None
        };
        let mut base: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("MDM_TEST_CONFIG")?)?)?;
        let directory = std::path::PathBuf::from(base["content"]["directory"].as_str().unwrap());
        if let Some(peer) = &peer {
            base["content"]["imports"][&peer.logical] = json!([{"base":format!("{}artifacts/",peer.base),"addresses":[peer.address],"private_ca":peer.ca}]);
        }
        let (router, execution, runtime) = crate::api::application_fixture(
            serde_json::from_value(base.clone())?,
            Arc::new(crate::clock::SystemClock),
            monotonic(),
            database(&base).await?,
            None,
            database(&base)
                .await?
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
        )
        .await?;
        let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
            "127.0.0.1".parse()?,
        )));
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
        let mut user = Browser {
            network: Some((client.clone(), origin.clone())),
            ..authority::Authority::open().await?.browser("admin")?
        };
        let subject = browser_subject(&user, &router).await?;
        let grants = [
            "resource_read",
            "resource_write",
            "software_read",
            "software_write",
            "software_approve",
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
        crate::test_support::identity::set_grants(case_tenant(), &subject, grants).await?;
        let source = peer.as_ref().map_or_else(
            || case::name("private-fixture").to_owned(),
            |peer| peer.logical.clone(),
        );
        let source_path = format!("/api/v3/software/sources/{source}/revisions/1");
        let registered=write(&mut user,&router,&source_path,0,json!({"action":"register","definition":{"id":source,"revision":"1","kind":"private","location":null,"publishers":[]}})).await?;
        write(
            &mut user,
            &router,
            &source_path,
            1,
            json!({"action":"approve","evidence":["source-review"]}),
        )
        .await?;
        Ok(Self {
            directory,
            router,
            execution,
            runtime,
            user,
            client,
            origin,
            subject,
            registered,
            peer,
            _server: server,
        })
    }
}
pub(crate) async fn write(
    browser: &mut Browser,
    router: &Router,
    path: &str,
    revision: u64,
    input: Value,
) -> Result<Value> {
    let body = json!({"operationId":Uuid::new_v4(),"expectedRevision":revision,"input":input});
    let response = browser.call(router, Method::POST, path, Some(body)).await?;
    ensure!(response.0 == StatusCode::OK, "{path}: {response:?}");
    Ok(response.1)
}

pub(crate) async fn create_software_version(
    user: &mut Browser,
    router: &Router,
    mut definition: Value,
) -> Result<(String, Value)> {
    let resource = Uuid::new_v4().to_string();
    definition["package"] = json!(format!("Private.{resource}"));
    let path = format!("/api/v3/resources/{resource}");
    write(
        user,
        router,
        &path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    write(user, router, &path, 1, json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    let read = user
        .call(
            router,
            Method::GET,
            &format!("/api/v3/software/resources/{resource}/versions/v1"),
            None,
        )
        .await?;
    ensure!(read.0 == StatusCode::OK, "read dependency: {read:?}");
    Ok((resource, read.1["resourceDigest"].clone()))
}
impl Fixture {
    pub(crate) async fn seed_content(&self, bytes: &[u8]) -> Result<rss_mdm_resource::Artifact> {
        let mut user = self.user.clone();
        let definition =
            publication_support::private_definition(self.registered["snapshot"].clone(), bytes);
        let (id, _) = create_software_version(&mut user, &self.router, definition).await?;
        let cookie = user
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        let response = self.client.post(format!("{}/api/v3/resources/{id}/content?version=v1&variant=default&platform=windows&architecture=x86_64&operation={}", self.origin, Uuid::new_v4()))
            .header("host", "mdm.example.test").header("origin", "https://mdm.example.test")
            .header("x-identity-request", "1").header("x-csrf-token", user.csrf.as_ref().unwrap())
            .header("cookie", cookie).header("content-type", "application/octet-stream")
            .body(bytes.to_vec()).send().await?;
        ensure!(
            response.status() == StatusCode::CREATED,
            "fixture content upload: {}",
            response.status()
        );
        Ok(rss_mdm_resource::Artifact::new(
            rss_mdm_resource::Id::new("installer")?,
            bytes.len() as u64,
            rss_mdm_resource::Digest::of(bytes),
        )?)
    }
}
