//! Production Nginx rules, management middleware, authentic session and real telemetry provider.
use crate::authority_t2_support::{Account, Context};
use anyhow::{Context as _, Result};
use std::{path::Path, sync::Arc, time::Duration};
pub(super) struct Http {
    task: tokio::task::JoinHandle<()>,
    gateway: tokio::process::Child,
    _directory: tempfile::TempDir,
    base: String,
    origin: String,
    cookie: String,
    csrf: String,
    buffers: Arc<tokio::sync::Semaphore>,
    client: reqwest::Client,
}
impl Drop for Http {
    fn drop(&mut self) {
        let _ = self.gateway.start_kill();
        self.task.abort();
    }
}
impl Http {
    pub async fn open(
        c: &Context,
        service: Arc<rss_mdm_telemetry_service::Service>,
        account: &Account,
    ) -> Result<Self> {
        Self::with_timeout(c, service, account, Duration::from_secs(8)).await
    }
    pub async fn with_timeout(
        c: &Context,
        service: Arc<rss_mdm_telemetry_service::Service>,
        account: &Account,
        timeout: Duration,
    ) -> Result<Self> {
        use rss_mdm_management_http::{
            authorization::http::{AuthenticationState, mount_protection},
            boundary,
            identity::Identity,
        };
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = tcp.local_addr()?;
        let port = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let origin = format!("https://localhost:{port}");
        let identity = Identity {
            authority: c.authority.clone(),
            rp_generation: rss_identity_postgres::RpGeneration::new(1)?,
            webauthn: rss_identity_postgres::WebauthnAuthority::new(
                c.authority.clone(),
                "localhost".into(),
                url::Url::parse(&origin)?,
            )?,
            http: rss_identity_http_axum::HttpConfig::new(&origin, Duration::from_secs(8))?,
        };
        rss_mdm_http_contract::route_module! {struct Mounted for [Browser]{telemetry at "/api/v1/tenants/{tenant}"}}
        let mounted = Mounted {
            telemetry: rss_mdm_management_http::telemetry::routes(Some(service)),
        }
        .assemble();
        let buffers = Arc::new(tokio::sync::Semaphore::new(128 * 1024 * 1024));
        let router = boundary::wrap(
            mount_protection(
                mounted,
                Some(Arc::new(AuthenticationState {
                    identity: Arc::new(identity),
                    access: c.access(),
                })),
                false,
            ),
            boundary::Envelope {
                request_timeout: timeout,
                profile: rss_mdm_install_support::StorageProfile::Mdm,
                host: format!("localhost:{port}"),
                clock: crate::clock::monotonic(),
                audit_store: c.audit.clone(),
                buffered_bytes: buffers.clone(),
            },
        )
        .into_axum()
        .layer(axum::Extension(c.execution()));
        let bindings = c
            .inputs
            .directory
            .parent()
            .context("T2 certificate directory")?;
        let directory = tempfile::tempdir()?;
        let mut gateway = tokio::process::Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../hack/gateway_fixture.py"))
            .arg(directory.path())
            .arg(bindings)
            .arg(address.to_string())
            .arg(port.to_string())
            .kill_on_drop(true)
            .spawn()?;
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                bindings.join("ca.crt"),
            )?)?)
            .timeout(Duration::from_secs(15))
            .build()?;
        let rss_mdm_authorization_service::credential::RequestCredential::Cookie(secret) =
            account.credential()?
        else {
            anyhow::bail!("session required");
        };
        let identity = uuid::Uuid::new_v4().to_string();
        let ready = identity.clone();
        let router = router.route("/readyz", axum::routing::get(move || async move { ready }));
        let task = tokio::spawn(async move {
            axum::serve(tcp, router).await.unwrap();
        });
        let startup = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = gateway.try_wait()? {
                    anyhow::bail!("production gateway exited: {status}");
                }
                if let Ok(response) = client.get(format!("{origin}/readyz")).send().await
                    && response.text().await? == identity
                {
                    return anyhow::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if !matches!(&startup, Ok(Ok(()))) {
            task.abort();
        }
        startup??;
        Ok(Self {
            task,
            gateway,
            _directory: directory,
            base: format!("{origin}/api/v1/tenants/{}", c.tenant),
            origin,
            cookie: format!("__Host-identity-session={}", secret.expose()),
            csrf: secret.csrf(),
            buffers,
            client,
        })
    }
    pub async fn stalled_body(&self) -> Result<()> {
        use futures::StreamExt;
        let chunks = futures::stream::iter([Ok::<_, std::io::Error>(vec![b'{'; 64])])
            .chain(futures::stream::pending());
        let available = self.buffers.available_permits();
        let send = self
            .client
            .post(format!("{}/telemetry/history", self.base))
            .header("origin", &self.origin)
            .header("cookie", &self.cookie)
            .header("x-csrf-token", &self.csrf)
            .header("content-type", "application/json")
            .body(reqwest::Body::wrap_stream(chunks))
            .send();
        let observe = async {
            tokio::time::timeout(Duration::from_secs(2), async {
                while self.buffers.available_permits() == available {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
        };
        let (response, observed) = tokio::join!(send, observe);
        observed?;
        let response = response?;
        assert_eq!(response.status(), 504);
        assert_eq!(
            response.json::<serde_json::Value>().await?["code"],
            "request_deadline"
        );
        assert_eq!(self.buffers.available_permits(), available);
        Ok(())
    }
    pub async fn call(
        &self,
        path: &str,
        input: serde_json::Value,
    ) -> Result<(u16, serde_json::Value)> {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .header("origin", &self.origin)
            .header("cookie", &self.cookie)
            .header("x-csrf-token", &self.csrf)
            .header("x-identity-request", "1")
            .json(&input)
            .send()
            .await?;
        let status = response.status().as_u16();
        let raw = response.text().await?;
        Ok((status, serde_json::from_str(&raw)?))
    }
    pub async fn post(&self, path: &str, input: serde_json::Value) -> Result<serde_json::Value> {
        let (status, value) = self.call(path, input).await?;
        anyhow::ensure!(status == 200, "{path}: {status} {value}");
        Ok(value)
    }
}
