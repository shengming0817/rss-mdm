//! Verified TLS transport to the actual management handlers with a real authorized subject.
use crate::authority_t2_support::Context;
use anyhow::Result;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};
struct Listener {
    tcp: tokio::net::TcpListener,
    tls: TlsAcceptor,
}
impl axum::serve::Listener for Listener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (socket, address) = self.tcp.accept().await.expect("TLS test listener");
            if let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_secs(5), self.tls.accept(socket)).await
            {
                return (stream, address);
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}
pub(super) struct Http {
    task: tokio::task::JoinHandle<()>,
    base: String,
    client: reqwest::Client,
}
impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Http {
    pub async fn open(
        c: &Context,
        service: Arc<rss_mdm_telemetry_service::Service>,
        proof: Arc<rss_mdm_authorization_service::context::AuthorizedPrincipal>,
    ) -> Result<Self> {
        let tenant = c.tenant.to_string();
        let access = c.access();
        let sessions = rss_mdm_authorization_service::session::SessionAuthority::new(
            c.authority.clone(),
            c.tenant,
        );
        let router = rss_mdm_management_http::telemetry::routes(Some(service))
            .into_axum()
            .layer(axum::middleware::from_fn(
                move |mut request: axum::extract::Request, next: axum::middleware::Next| {
                    let proof = proof.clone();
                    let tenant = tenant.clone();
                    let sessions = sessions.clone();
                    let deadline = access.now() + Duration::from_secs(8);
                    async move {
                        let audit = rss_mdm_audit_integration::RequestAudit::new(
                            rss_mdm_audit_integration::Origin::Request,
                            rss_mdm_install_support::StorageProfile::Mdm,
                            tenant,
                            "telemetry-query-t2",
                            rss_mdm_audit_integration::AuditIntent::Routine,
                        );
                        proof.bind_audit(&audit).unwrap();
                        request.extensions_mut().insert(audit);
                        request.extensions_mut().insert(
                            rss_mdm_authorization_service::context::RequestAuth {
                                proof,
                                sessions,
                                deadline,
                            },
                        );
                        next.run(request).await
                    }
                },
            ));
        let directory = c.inputs.directory.parent().unwrap();
        let cert = CertificateDer::from_pem_file(directory.join("server.crt"))?;
        let key = PrivateKeyDer::from_pem_file(directory.join("server.key"))?;
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                directory.join("ca.crt"),
            )?)?)
            .timeout(Duration::from_secs(15))
            .build()?;
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("https://localhost:{}", tcp.local_addr()?.port());
        let task = tokio::spawn(async move {
            axum::serve(
                Listener {
                    tcp,
                    tls: TlsAcceptor::from(Arc::new(tls)),
                },
                router,
            )
            .await
            .unwrap();
        });
        Ok(Self { task, base, client })
    }
    pub async fn call(
        &self,
        path: &str,
        input: serde_json::Value,
    ) -> Result<(u16, serde_json::Value)> {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
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
