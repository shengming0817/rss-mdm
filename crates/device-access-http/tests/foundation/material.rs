use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::{da, enroll, pki};
use rss_mdm_native_protection::Protector;
use rss_mdm_task_trust::{Signing, Use};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
pub struct Material {
    pub directory: std::path::PathBuf,
    pub protection: Arc<Protector>,
    port: u16,
    _provider: tokio::process::Child,
}
pub struct Server {
    pub origin: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl registration::certificate_issuance::Clock for context::Timer {
    fn unix_seconds(&self) -> std::result::Result<i64, registration::Error> {
        Ok(now())
    }
}
impl Material {
    pub async fn new(c: &Context) -> Result<Self> {
        let directory = c.inputs.directory.join(format!("da-{}", Uuid::new_v4()));
        let mut child = tokio::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../hack/da_foundation_materials.py"
            ))
            .arg(&directory)
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let ready = tokio::time::timeout(Duration::from_secs(60), lines.next_line())
            .await??
            .ok_or_else(|| anyhow::anyhow!("issuer did not start"))?;
        let value: serde_json::Value = serde_json::from_str(&ready)?;
        Ok(Self {
            directory,
            port: value["port"].as_u64().unwrap() as u16,
            _provider: child,
            protection: Arc::new(Protector::with_fingerprint(
                &std::fs::read(c.inputs.directory.join("native.key"))?,
                &[],
                &std::fs::read(c.inputs.directory.join("fingerprint.key"))?,
            )?),
        })
    }
    pub fn csr(&self, index: u8) -> Result<String> {
        Ok(STANDARD.encode(std::fs::read(
            self.directory.join(format!("device{index}.der")),
        )?))
    }
    pub fn issued_count(&self) -> Result<usize> {
        Ok(
            std::fs::read_to_string(self.directory.join("issued.jsonl"))?
                .lines()
                .count(),
        )
    }
    async fn der(&self, kind: &str, path: &str) -> Result<Vec<u8>> {
        let result = tokio::process::Command::new("openssl")
            .args([kind, "-in"])
            .arg(self.directory.join(path))
            .args(["-outform", "DER"])
            .output()
            .await?;
        anyhow::ensure!(result.status.success(), "DER conversion failed");
        Ok(result.stdout)
    }
    pub async fn assemble(
        &self,
        c: &Context,
    ) -> Result<Arc<registration::agent::da::RegistrationService>> {
        let root = self.der("x509", "task-trust-ca/ca.pem").await?;
        let crl = self.der("crl", "task-trust-ca/ca.crl").await?;
        let trust: pki::Trust = serde_json::from_value(
            serde_json::json!({"version":1,"service_id":c.inputs.installation.instance_id,"origin":"https://localhost","tenant":c.tenant.to_string(),"purpose":"da_device","revision":1,"issuers":[{"digest":format!("{:x}",Sha256::digest(&root)),"mode":"active","certificate":STANDARD.encode(&root),"root":STANDARD.encode(&root),"crl":STANDARD.encode(&crl),"root_crl":STANDARD.encode(&crl),"provisioner":"rss-da-device","kid":"da-test"}]}),
        )?;
        let identity = Arc::new(
            rss_mdm_device_trust::device_identity::DeviceIdentityTrust::from_trust(
                rss_mdm_device_trust::DeviceTrust::new(
                    trust.clone(),
                    pki::Purpose::DaDevice,
                    now(),
                )?,
                2,
            )?,
        );
        // Existing published issuer is a prerequisite; issuance/activation are never seeded.
        sqlx::query("INSERT INTO rss_da.pki_issuers(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1::uuid,'da_device',$2,1,'active',$3,'step_ca',$4)").bind(c.tenant.to_string()).bind(&trust.issuers[0].digest).bind(serde_json::to_vec(&trust.issuers[0])?).bind(identity.expires()).execute(&c.operator).await?;
        sqlx::query("INSERT INTO rss_da.pki_trust(tenant_id,purpose,revision,body) VALUES($1::uuid,'da_device',1,$2)").bind(c.tenant.to_string()).bind(serde_json::to_vec(&trust)?).execute(&c.operator).await?;
        let client = Arc::new(rss_mdm_pki_service::StepCa::at_address(
            rss_mdm_pki_service::Configuration {
                origin: format!("https://localhost:{}", self.port),
                provisioner: "rss-da-device".into(),
                kid: "da-test".into(),
            },
            &std::fs::read(self.directory.join("task-trust-ca/ca.pem"))?,
            &std::fs::read(self.directory.join("provider.pk8"))?,
            format!("127.0.0.1:{}", self.port).parse()?,
        )?);
        let providers = Arc::new(rss_mdm_pki_service::providers::Providers::new(vec![
            rss_mdm_pki_service::providers::Provider {
                purpose: pki::Purpose::DaDevice,
                issuer: trust.issuers[0].digest.clone(),
                client,
                scep_url: None,
            },
        ])?);
        let clock = Arc::new(context::Timer);
        let issuer = Arc::new(registration::certificate_issuance::DeviceIssuer::new(
            DA,
            providers,
            2,
            true,
            identity,
            clock.clone(),
        )?);
        Ok(Arc::new(registration::agent::da::RegistrationService::new(
            registration::agent::da::Assembly {
                cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
                    ring::hmac::HMAC_SHA256,
                    &[5; 32],
                )),
                tenant: c.tenant,
                store: Arc::new(registration::Store::for_device_access(c.access.clone())),
                audit: c.access_audit.clone(),
                access_audit: c.access_audit.clone(),
                issuer,
                clock,
                protection: self.protection.clone(),
            },
        )?))
    }
    pub async fn listen(&self, mut state: rss_mdm_device_access_http::Services) -> Result<Server> {
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        state.host = format!("localhost:{}", addr.port());
        let cert = CertificateDer::pem_file_iter(self.directory.join("server.pem"))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(self.directory.join("server.key"))?;
        let state = Arc::new(state);
        let task = tokio::spawn(async move {
            rss_mdm_device_access_http::tls::serve(listener, cert, key, state)
                .await
                .expect("DA TLS listener");
        });
        Ok(Server {
            origin: format!("https://localhost:{}/api/v1/da", addr.port()),
            task,
        })
    }
    pub fn client(&self, peer: Option<(&enroll::Candidate, u8)>) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
                self.directory.join("task-trust-ca/ca.pem"),
            )?)?)
            .timeout(Duration::from_secs(20));
        if let Some((certificate, index)) = peer {
            let mut pem = std::fs::read(self.directory.join(format!("device{index}.key")))?;
            for certificate in &certificate.certificate_chain {
                let der = STANDARD.decode(certificate)?;
                let encoded = STANDARD.encode(der);
                pem.extend_from_slice(b"\n-----BEGIN CERTIFICATE-----\n");
                for line in encoded.as_bytes().chunks(64) {
                    pem.extend_from_slice(line);
                    pem.push(b'\n');
                }
                pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
            }
            builder = builder.identity(reqwest::Identity::from_pem(&pem)?);
        }
        Ok(builder.build()?)
    }
}
pub fn state(
    c: &Context,
    registration: Arc<registration::agent::da::RegistrationService>,
    signing: Arc<Signing>,
    m: &Material,
) -> Result<rss_mdm_device_access_http::Services> {
    let trust = Arc::new(rss_mdm_task_trust::Service::for_configurations(
        c.tenant,
        signing,
        m.protection.clone(),
        c.access_audit.clone(),
    )?);
    let configurations = Arc::new(
        rss_mdm_task_trust::configuration::ConfigurationService::new(
            trust,
            std::num::NonZeroU32::new(3600).unwrap(),
        )?,
    );
    Ok(rss_mdm_device_access_http::Services {
        registrations: registration,
        configurations,
        authorization: c.authorization.clone(),
        sessions: c.sessions.clone(),
        audit: c.access_audit.clone(),
        host: String::new(),
        requests: Arc::new(tokio::sync::Semaphore::new(16)),
    })
}
pub async fn load(c: &Context, m: &Material, revision: u64) -> Result<Arc<Signing>> {
    let mut tx = c.access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let loaded = rss_mdm_task_trust::trust::load(
        DA,
        Use::DaConfiguration,
        &mut tx,
        c.tenant,
        revision,
        &m.protection,
    )
    .await?;
    tx.commit().await?;
    Ok(Arc::new(Signing::new(
        DA,
        Use::DaConfiguration,
        c.tenant,
        Some(loaded),
    )?))
}
pub async fn success<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let text = response.text().await?;
    anyhow::ensure!(status.is_success(), "HTTP {status}: {text}");
    Ok(serde_json::from_str(&text)?)
}
pub async fn empty(response: reqwest::Response) -> Result<()> {
    let status = response.status();
    let text = response.text().await?;
    anyhow::ensure!(status.is_success(), "HTTP {status}: {text}");
    Ok(())
}
pub fn verify(signed: &da::SignedConfiguration, trust: &da::ConfigurationTrust) -> Result<()> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let key = trust.keys.iter().find(|k| k.id == signed.key_id).unwrap();
    let bytes = signed.configuration.signing_bytes(&signed.key_id)?;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        URL_SAFE_NO_PAD.decode(&key.public_key)?,
    )
    .verify(&bytes, &URL_SAFE_NO_PAD.decode(&signed.signature)?)
    .map_err(|_| anyhow::anyhow!("DA signature"))?;
    Ok(())
}
pub async fn administrator(c: &Context) -> Result<String> {
    administrator_for(c, None).await
}
pub async fn device_administrator(c: &Context, device: &str) -> Result<String> {
    administrator_for(c, Some(device)).await
}
async fn administrator_for(c: &Context, device: Option<&str>) -> Result<String> {
    use rss_identity_core::account::{LoginKey, Password};
    use rss_mdm_authorization_service as access;
    let principal = Uuid::new_v4();
    let login = format!("da-{principal}");
    let password = "foundation-only-valid-password";
    let kdf = rss_identity_core::account::PasswordKdf::new();
    let hash = kdf.hash(Password::new(password.into())?).await?;
    let mut tx = c.seed().await?;
    sqlx::query(
        "INSERT INTO identity_authority.guard(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(c.tenant.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO identity_authority.accounts(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(principal)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO identity_authority.local_credentials(tenant_id,principal_id,login_key,password_hash) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(principal).bind(&login).bind(hash.as_str()).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO identity_authority.memberships(tenant_id,principal_id) VALUES($1::uuid,$2)",
    )
    .bind(c.tenant.to_string())
    .bind(principal)
    .execute(&mut *tx)
    .await?;
    let user = access::User {
        instance_id: c.inputs.installation.instance_id.clone(),
        tenant_id: c.tenant.to_string(),
        principal_id: principal.to_string(),
    };
    let rule = access::Rule {
        subject: access::Subject::User { user },
        grants: if let Some(device) = device {
            vec![access::Grant {
                operation: access::Permission::ConfigurationWrite,
                scope: access::Scope::Device { id: device.into() },
            }]
        } else {
            [
                access::Permission::Enrollment,
                access::Permission::Credentials,
                access::Permission::ConfigurationWrite,
                access::Permission::RegistrationConfigurationWrite,
                access::Permission::RegistrationConfigurationRead,
            ]
            .into_iter()
            .map(|operation| access::Grant {
                operation,
                scope: if operation.device() {
                    access::Scope::AllDevices
                } else {
                    access::Scope::Tenant
                },
            })
            .collect()
        },
    };
    sqlx::query("INSERT INTO rss_da.authorization_rules(tenant_id,instance,id,revision,document) VALUES($1::uuid,$2::uuid,$3,1,$4)").bind(c.tenant.to_string()).bind(&c.inputs.installation.instance_id).bind(Uuid::new_v4()).bind(serde_json::to_value(rule)?).execute(&mut *tx).await?;
    tx.commit().await?;
    let issued = c
        .authority
        .login_local_bearer(
            c.tenant,
            LoginKey::parse(&login)?,
            Password::new(password.into())?,
            rss_identity_postgres::AttemptSource::parse("da-foundation")?,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(10),
            ),
        )
        .await?;
    kdf.close();
    kdf.wait_closed().await;
    Ok(issued.secret().expose().into())
}
