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
                request_timeout: Duration::from_secs(8),
                profile: rss_mdm_install_support::StorageProfile::Mdm,
                host: format!("localhost:{port}"),
                clock: crate::clock::monotonic(),
                audit_store: c.audit.clone(),
                buffered_bytes: Arc::new(tokio::sync::Semaphore::new(128 * 1024 * 1024)),
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
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = gateway.try_wait()? {
                    anyhow::bail!("production gateway exited: {status}");
                }
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    return anyhow::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let task = tokio::spawn(async move {
            axum::serve(tcp, router).await.unwrap();
        });
        Ok(Self {
            task,
            gateway,
            _directory: directory,
            base: format!("{origin}/api/v1/tenants/{}", c.tenant),
            origin,
            cookie: format!("__Host-identity-session={}", secret.expose()),
            csrf: secret.csrf(),
            client,
        })
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
