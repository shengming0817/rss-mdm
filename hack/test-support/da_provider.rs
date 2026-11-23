//! Real certificate provider shared by the standalone and embedded DA host T2 tests.
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::{enroll, pki};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;
pub struct Provider {
    pub directory: std::path::PathBuf,
    pub port: u16,
    _provider: tokio::process::Child,
}
impl Provider {
    pub async fn new(parent: &std::path::Path) -> Result<Self> {
        let directory = parent.join(format!("da-{}", Uuid::new_v4()));
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
        })
    }
    pub fn csr(&self, index: u8) -> Result<String> {
        Ok(STANDARD.encode(std::fs::read(
            self.directory.join(format!("device{index}.der")),
        )?))
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
    pub async fn publish(
        &self,
        pool: &sqlx::PgPool,
        tenant: &str,
        instance: &str,
        device_origin: &str,
    ) -> Result<pki::Trust> {
        let root = self.der("x509", "task-trust-ca/ca.pem").await?;
        let crl = self.der("crl", "task-trust-ca/ca.crl").await?;
        let trust: pki::Trust = serde_json::from_value(
            serde_json::json!({"version":1,"service_id":instance,"origin":device_origin,"tenant":tenant,"purpose":"da_device","revision":1,"issuers":[{"digest":format!("{:x}",Sha256::digest(&root)),"mode":"active","certificate":STANDARD.encode(&root),"root":STANDARD.encode(&root),"crl":STANDARD.encode(&crl),"root_crl":STANDARD.encode(&crl),"provisioner":"rss-da-device","kid":"da-test"}]}),
        )?;
        let identity = Arc::new(
            rss_mdm_device_trust::device_identity::DeviceIdentityTrust::from_trust(
                rss_mdm_device_trust::DeviceTrust::new(
                    trust.clone(),
                    pki::Purpose::DaDevice,
                    time::OffsetDateTime::now_utc().unix_timestamp(),
                )?,
                2,
            )?,
        );
        // Existing published issuer is a prerequisite; issuance/activation are never seeded.
        sqlx::query("INSERT INTO rss_da.pki_issuers(tenant_id,purpose,digest,revision,state,chain,provider,not_after) VALUES($1::uuid,'da_device',$2,1,'active',$3,'step_ca',$4)").bind(tenant).bind(&trust.issuers[0].digest).bind(serde_json::to_vec(&trust.issuers[0])?).bind(identity.expires()).execute(pool).await?;
        sqlx::query("INSERT INTO rss_da.pki_trust(tenant_id,purpose,revision,body) VALUES($1::uuid,'da_device',1,$2)").bind(tenant).bind(serde_json::to_vec(&trust)?).execute(pool).await?;
        Ok(trust)
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
