//! Runtime configuration files and HTTPS observations. Infrastructure is owned by Compose/Kubernetes.
use super::{Error, Result, host::Binding, local::Journal};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Runtime files mounted by the deployment manifest.
    pub directory: PathBuf,
    /// Optional internal HTTPS endpoint; certificate identity remains product_origin.
    pub probe_address: Option<String>,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub trust_file: PathBuf,
    pub content_volume: Option<PathBuf>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GatewayTls {
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub trust_file: PathBuf,
    pub digest: String,
}
impl GatewayTls {
    pub(super) fn prepare(
        journal: &Journal,
        certificate: &Path,
        key: &Path,
        trust: &Path,
    ) -> Result<Self> {
        let certificate =
            crate::config::read(certificate, 128 * 1024, false).map_err(|_| Error::Input)?;
        let key = crate::config::read(key, 32768, true).map_err(|_| Error::Input)?;
        let trust = crate::config::read(trust, 128 * 1024, false).map_err(|_| Error::Input)?;
        let cert = openssl::x509::X509::from_pem(&certificate).map_err(|_| Error::Input)?;
        let private = openssl::pkey::PKey::private_key_from_pem(&key).map_err(|_| Error::Input)?;
        if !cert
            .public_key()
            .map_err(|_| Error::Input)?
            .public_eq(&private)
        {
            return Err(Error::Input);
        }
        reqwest::Certificate::from_pem(&trust).map_err(|_| Error::Input)?;
        let mut digest = Sha256::new();
        for bytes in [certificate.as_slice(), key.as_slice(), trust.as_slice()] {
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
        Ok(Self {
            certificate_file: journal.secret("gateway.crt", &certificate)?,
            private_key_file: journal.secret("gateway.key", &key)?,
            trust_file: journal.secret("gateway-ca.crt", &trust)?,
            digest: format!("{:x}", digest.finalize()),
        })
    }
    fn apply(&self, config: &mut Config) {
        config.certificate_file = self.certificate_file.clone();
        config.private_key_file = self.private_key_file.clone();
        config.trust_file = self.trust_file.clone();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Applied {
    pub host_id: uuid::Uuid,
    pub operation_id: uuid::Uuid,
    pub revision: u64,
    pub material_digest: String,
    pub process_generation: uuid::Uuid,
    pub tenant_id: String,
    pub instance_id: String,
}
fn public_file(name: &str) -> bool {
    matches!(
        name,
        "ca_file"
            | "tls_root_file"
            | "private_ca_file"
            | "certificate_file"
            | "trust_file"
            | "profile_certificate_file"
            | "apns_certificate_file"
    )
}
fn project(
    value: &mut Value,
    journal: &Journal,
    mounts: &mut BTreeMap<String, PathBuf>,
    local: bool,
) -> Result<()> {
    match value {
        Value::Object(values) => {
            for (name, value) in values {
                if name.ends_with("_file") && value.is_string() {
                    project_file(value, journal, mounts, !public_file(name), local)?;
                } else if matches!(name.as_str(), "key_files" | "credential_keys") {
                    for key in value.as_object_mut().ok_or(Error::Input)?.values_mut() {
                        project_file(key, journal, mounts, true, local)?;
                    }
                } else if matches!(
                    name.as_str(),
                    "apple_material_roots" | "historical_files" | "ca_files"
                ) {
                    for root in value.as_array_mut().ok_or(Error::Input)? {
                        project_file(root, journal, mounts, name == "historical_files", local)?;
                    }
                } else {
                    project(value, journal, mounts, local)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                project(value, journal, mounts, local)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn project_file(
    value: &mut Value,
    journal: &Journal,
    mounts: &mut BTreeMap<String, PathBuf>,
    private: bool,
    local: bool,
) -> Result<()> {
    let source = Path::new(value.as_str().ok_or(Error::Input)?);
    if !source.is_absolute() {
        return Err(Error::Input);
    }
    let bytes = crate::config::read(source, 64 * 1024 * 1024, private).map_err(|_| Error::Input)?;
    let filename = format!(
        "input-{:x}",
        if local {
            Sha256::digest(bytes.as_slice())
        } else {
            Sha256::digest(source.as_os_str().as_encoded_bytes())
        }
    );
    let path = journal.secret(&filename, &bytes)?;
    mounts.insert(filename.clone(), path.clone());
    *value = if local {
        json!(path)
    } else {
        Value::String(format!("/run/mdm/{filename}"))
    };
    Ok(())
}
/// Freeze deployment file inputs under content-addressed private names before computing an application digest.
pub(super) fn freeze(runtime: &mut Value, journal: &Journal) -> Result<()> {
    project(runtime, journal, &mut BTreeMap::new(), true)
}

/// Export runtime inputs only. This function never starts, stops or inspects containers.
pub async fn prepare(directory: &Path, config: &Config, runtime: &Value) -> Result<()> {
    let decoded: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Input)?;
    let compiled = decoded.compile().map_err(|_| Error::Input)?;
    let decoded = &compiled.config;
    if !decoded.listen.ip().is_loopback() || decoded.trusted_gateway != decoded.listen.ip() {
        return Err(Error::Input);
    }
    let origin = url::Url::parse(&decoded.product_origin).map_err(|_| Error::Input)?;
    let hostname = origin.host_str().ok_or(Error::Input)?;
    if origin.scheme() != "https"
        || !hostname
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return Err(Error::Input);
    }
    let owner = Journal::open(&directory.join(format!(
        "rss-mdm-{}",
        decoded.runtime_binding.host_id.simple()
    )))?;
    let mut effective = config.clone();
    if let Some(tls) = owner.load::<GatewayTls>("gateway-tls.json")? {
        tls.apply(&mut effective);
    }
    let server = Journal::open(&config.directory.join("server"))?;
    let gateway = Journal::open(&config.directory.join("gateway"))?;
    let mut projected = runtime.clone();
    project(&mut projected, &server, &mut BTreeMap::new(), false)?;
    server.save("runtime.json", &projected)?;
    let certificate = crate::config::read(&effective.certificate_file, 128 * 1024, false)
        .map_err(|_| Error::Input)?;
    let key =
        crate::config::read(&effective.private_key_file, 32768, true).map_err(|_| Error::Input)?;
    gateway.replace("tls.crt", &certificate)?;
    gateway.replace("tls.key", &key)?;
    let authority = &origin[url::Position::BeforeHost..url::Position::AfterPort];
    let nginx = include_str!("../../../../deployment/nginx.conf")
        .replace("127.0.0.1:8081", &decoded.listen.to_string())
        .replace("listen 443 ssl;", "listen 8445 ssl;")
        .replace(
            "server_name mdm.example.test;",
            &format!("server_name {hostname};"),
        )
        .replace(
            "proxy_set_header Host mdm.example.test;",
            &format!("proxy_set_header Host {authority};"),
        )
        .replace("/private/mdm-tls.crt", "/run/gateway/tls.crt")
        .replace("/private/mdm-tls.key", "/run/gateway/tls.key")
        .replace("/run/config/ui.json", "/run/gateway/ui.json")
        .replace("/run/config/mdm.json", "/run/gateway/mdm.json");
    gateway.replace("nginx.conf", nginx.as_bytes())?;
    let public = super::public_configuration::read(decoded).await?;
    gateway.save("ui.json", &public.identity)?;
    gateway.save("mdm.json", &public.mdm)?;
    owner.save("requested-runtime.json", runtime)?;
    owner.save("runtime-files.json", &effective)?;
    Ok(())
}
/// Publish files and observe an already running host. Pending until operations restarts it.
pub async fn apply(directory: &Path, config: &Config, runtime: &Value) -> Result<Applied> {
    prepare(directory, config, runtime).await?;
    let decoded: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Input)?;
    let owner = Journal::open(&directory.join(format!(
        "rss-mdm-{}",
        decoded.runtime_binding.host_id.simple()
    )))?;
    let effective: Config = owner.load("runtime-files.json")?.ok_or(Error::Corrupt)?;
    let root =
        crate::config::read(&effective.trust_file, 128 * 1024, false).map_err(|_| Error::Input)?;
    let mut client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8))
        .add_root_certificate(reqwest::Certificate::from_pem(&root).map_err(|_| Error::Input)?);
    let mut origin = url::Url::parse(&decoded.product_origin).map_err(|_| Error::Input)?;
    if let Some(endpoint) = &effective.probe_address {
        let addresses = tokio::net::lookup_host(endpoint)
            .await
            .map_err(|_| Error::Storage)?
            .collect::<Vec<_>>();
        let port = addresses.first().ok_or(Error::Input)?.port();
        client = client.resolve_to_addrs(origin.host_str().ok_or(Error::Input)?, &addresses);
        origin.set_port(Some(port)).map_err(|_| Error::Input)?;
    }
    let applied = observe(
        &client.build().map_err(|_| Error::Input)?,
        origin.as_str().trim_end_matches('/'),
        &decoded.runtime_binding,
        &decoded.identity.tenant_id,
        &decoded.identity.instance_id,
    )
    .await?;
    owner.save("applied.json", &applied)?;
    Ok(applied)
}
fn matches(value: &Applied, binding: &Binding, tenant: &str, instance: &str) -> bool {
    value.host_id == binding.host_id
        && value.operation_id == binding.operation_id
        && value.revision == binding.revision
        && value.material_digest == binding.material_digest
        && value.tenant_id == tenant
        && value.instance_id == instance
        && !value.process_generation.is_nil()
}
async fn observe(
    client: &reqwest::Client,
    origin: &str,
    binding: &Binding,
    tenant: &str,
    instance: &str,
) -> Result<Applied> {
    let mut response = client
        .get(format!("{origin}/readyz"))
        .send()
        .await
        .map_err(|_| Error::Storage)?;
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > 16384) {
        return Err(Error::Storage);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Storage)? {
        if chunk.len() > 16384usize.saturating_sub(bytes.len()) {
            return Err(Error::Storage);
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
    if value["ready"] != true {
        return Err(Error::Storage);
    }
    let observation: Applied =
        serde_json::from_value(value["observation"].clone()).map_err(|_| Error::Storage)?;
    if !matches(&observation, binding, tenant, instance) {
        return Err(Error::Conflict);
    }
    Ok(observation)
}

#[cfg(test)]
#[path = "../../tests/setup/runtime_files.rs"]
mod tests;
