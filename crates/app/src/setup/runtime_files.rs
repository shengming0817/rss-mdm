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

/// Native listeners share only the backend namespace; the gateway has its own.
pub(super) fn validate_listeners(config: &crate::config::Config) -> Result<()> {
    let mut addresses = vec![config.listen];
    if let Some(windows) = &config.native_protocols.windows {
        addresses.extend([windows.enrollment.listen, windows.management.listen]);
        addresses.extend(
            windows
                .additional_management
                .iter()
                .map(|endpoint| endpoint.listen),
        );
    }
    if let Some(apple) = &config.native_protocols.apple {
        addresses.push(apple.management.listen);
    }
    if let crate::agent_pki::Config::StepCa { endpoint, .. } = &config.agent_pki {
        addresses.push(endpoint.listen);
    }
    for (i, address) in addresses.iter().enumerate() {
        if address.port() == 0
            || addresses[..i].iter().any(|other| {
                other.port() == address.port()
                    && (other.ip() == address.ip()
                        || other.ip().is_unspecified()
                        || address.ip().is_unspecified())
            })
        {
            return Err(Error::Input);
        }
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Runtime files mounted by the deployment manifest.
    pub directory: PathBuf,
    /// Shared ingress output for all tenant hosts on this gateway.
    pub gateway_directory: PathBuf,
    /// Optional internal HTTPS endpoint; certificate identity remains product_origin.
    pub probe_address: Option<String>,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub trust_file: PathBuf,
    pub content_volume: Option<PathBuf>,
}
impl Config {
    pub(super) fn content_directory(&self) -> PathBuf {
        self.content_volume
            .clone()
            .unwrap_or_else(|| self.directory.join("content"))
    }
    pub(super) fn prepare_content_storage(&self) -> Result<Value> {
        let directory = self.content_directory();
        if !directory.is_absolute() {
            return Err(Error::Input);
        }
        std::fs::create_dir_all(&directory).map_err(|_| Error::Storage)?;
        Ok(json!({"kind":"volume","directory":directory}))
    }
    /// Keep the deployed volume in cold backups even when Content is disabled or uses S3.
    pub(super) fn content_snapshot(&self, runtime: &Value) -> Result<PathBuf> {
        let directory = self.content_directory();
        if runtime["content"]["storage"]["kind"] == "volume"
            && runtime["content"]["storage"]["directory"] != json!(directory)
        {
            return Err(Error::Conflict);
        }
        Ok(directory)
    }
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
    optional: bool,
) -> Result<()> {
    match value {
        Value::Object(values) => {
            for (name, value) in values {
                // Only device channel material trees are optional; core database/identity/protection inputs are not.
                let optional = optional
                    || matches!(
                        name.as_str(),
                        "native_protocols" | "agent_pki" | "device_pki" | "apple_material_roots"
                    );
                if name.ends_with("_file") && value.is_string() {
                    project_file(value, journal, mounts, !public_file(name), local, optional)?;
                } else if matches!(name.as_str(), "key_files" | "credential_keys") {
                    for key in value.as_object_mut().ok_or(Error::Input)?.values_mut() {
                        project_file(key, journal, mounts, true, local, optional)?;
                    }
                } else if matches!(
                    name.as_str(),
                    "apple_material_roots" | "historical_files" | "ca_files"
                ) {
                    for root in value.as_array_mut().ok_or(Error::Input)? {
                        project_file(
                            root,
                            journal,
                            mounts,
                            name == "historical_files",
                            local,
                            optional,
                        )?;
                    }
                } else {
                    project(value, journal, mounts, local, optional)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                project(value, journal, mounts, local, optional)?;
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
    optional: bool,
) -> Result<()> {
    let source = Path::new(value.as_str().ok_or(Error::Input)?);
    if !source.is_absolute() && !(optional && source.as_os_str().is_empty()) {
        return Err(Error::Input);
    }
    let bytes = match crate::config::read(source, 64 * 1024 * 1024, private) {
        Ok(bytes) => bytes,
        Err(_) if optional => {
            // No stand-in secret or stale copied material: the running channel observes an absent input.
            if !local {
                *value = Value::String(format!(
                    "/run/mdm/unavailable-{:x}",
                    Sha256::digest(source.as_os_str().as_encoded_bytes())
                ));
            }
            return Ok(());
        }
        Err(_) => return Err(Error::Input),
    };
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
    project(runtime, journal, &mut BTreeMap::new(), true, false)
}

// ref: smallstep/certificates scep/api/api.go@v0.30.2; nginx ngx_http_proxy_module.
// Only exact device SCEP paths are published. Upstream CA APIs stay on their private origin.
fn scep_locations(config: &crate::config::Config, gateway: &Journal) -> Result<String> {
    let origin = url::Url::parse(&config.product_origin).map_err(|_| Error::Input)?;
    let mut routes = BTreeMap::new();
    for provider in &config.device_pki {
        let Some(endpoint) = &provider.scep_url else {
            continue;
        };
        let endpoint =
            rss_mdm_pki_service::providers::scep_endpoint(endpoint).map_err(|_| Error::Input)?;
        if endpoint.origin() != origin.origin() {
            continue;
        }
        if !matches!(
            provider.purpose,
            rss_mdm_agent_wire::pki::Purpose::Apple
                | rss_mdm_agent_wire::pki::Purpose::AgentBootstrap
        ) {
            return Err(Error::Input);
        }
        let provisioner = endpoint.path().strip_prefix("/scep/").ok_or(Error::Input)?;
        let ca = url::Url::parse(&provider.origin).map_err(|_| Error::Input)?;
        if ca.scheme() != "https" || ca.origin().ascii_serialization() != provider.origin {
            return Err(Error::Input);
        }
        let Ok(root) = crate::config::read(&provider.tls_root_file, 131072, false) else {
            // reason: an unavailable optional CA has no public SCEP route; the catch-all rejects it.
            continue;
        };
        if reqwest::Certificate::from_pem(&root).is_err() {
            // reason: malformed optional CA input must not make the entire gateway configuration unloadable.
            continue;
        }
        let name = format!("scep-root-{:x}.crt", Sha256::digest(&root));
        let route = (
            provider.origin.clone(),
            provisioner.to_owned(),
            name.clone(),
        );
        if let Some(previous) = routes.insert(endpoint.path().to_owned(), route.clone())
            && previous != route
        {
            return Err(Error::Input);
        }
        gateway.replace(&name, &root)?;
    }
    let mut output = String::new();
    for (path, (ca, provisioner, root)) in routes {
        let url = url::Url::parse(&ca).map_err(|_| Error::Input)?;
        let host = url.host_str().ok_or(Error::Input)?;
        if !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        {
            return Err(Error::Input);
        }
        let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
        for suffix in ["", "/pkiclient.exe"] {
            output.push_str(&format!(
                r#"
        location = {path}{suffix} {{
            if ($request_method !~ ^(GET|POST)$) {{ return 405; }}
            if ($arg_operation !~ ^(GetCACert|GetCACaps|PKIOperation)$) {{ return 400; }}
            limit_req zone=mdm_api burst=20 nodelay;
            client_max_body_size 2m;
            proxy_pass_request_headers off;
            proxy_set_header Host {authority};
            proxy_set_header Content-Type $content_type;
            proxy_ssl_server_name on;
            proxy_ssl_name {host};
            proxy_ssl_verify on;
            proxy_ssl_verify_depth 3;
            proxy_ssl_trusted_certificate /run/gateway/{root};
            proxy_connect_timeout 5s;
            proxy_read_timeout 30s;
            proxy_pass {ca}/scep/{provisioner};
        }}
"#
            ));
        }
    }
    Ok(output)
}

/// Export runtime inputs only. This function never starts, stops or inspects containers.
pub async fn prepare(directory: &Path, config: &Config, runtime: &Value) -> Result<()> {
    config.content_snapshot(runtime)?;
    let decoded: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Input)?;
    validate_listeners(&decoded)?;
    let compiled = decoded.compile().map_err(|_| Error::Input)?;
    let decoded = &compiled.config;
    if decoded.listen.ip().is_unspecified() || decoded.trusted_gateway.is_unspecified() {
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
    let ingress = Journal::open(&config.gateway_directory)?;
    let host_id = decoded.runtime_binding.host_id.simple().to_string();
    let gateway = Journal::open(&config.gateway_directory.join(&host_id))?;
    let mut projected = runtime.clone();
    project(&mut projected, &server, &mut BTreeMap::new(), false, false)?;
    server.save("runtime.json", &projected)?;
    let certificate = crate::config::read(&effective.certificate_file, 128 * 1024, false)
        .map_err(|_| Error::Input)?;
    let key =
        crate::config::read(&effective.private_key_file, 32768, true).map_err(|_| Error::Input)?;
    gateway.replace("tls.crt", &certificate)?;
    gateway.replace("tls.key", &key)?;
    let authority = &origin[url::Position::BeforeHost..url::Position::AfterPort];
    let nginx = include_str!("../../../../deployment/http.conf")
        .replace("127.0.0.1:8081", &decoded.listen.to_string())
        .replace(
            "server_name mdm.example.test;",
            &format!("server_name {hostname};"),
        )
        .replace(
            "proxy_set_header Host mdm.example.test;",
            &format!("proxy_set_header Host {authority};"),
        )
        .replace(
            "/private/mdm-tls.crt",
            &format!("/run/gateway/{host_id}/tls.crt"),
        )
        .replace(
            "/private/mdm-tls.key",
            &format!("/run/gateway/{host_id}/tls.key"),
        )
        .replace(
            "/run/config/ui.json",
            &format!("/run/gateway/{host_id}/ui.json"),
        )
        .replace(
            "/run/config/mdm.json",
            &format!("/run/gateway/{host_id}/mdm.json"),
        );
    let nginx = nginx.replace("# MDM_SCEP_LOCATIONS", &scep_locations(decoded, &gateway)?);
    let nginx = nginx
        .replace("mdm_backend", &format!("mdm_backend_{host_id}"))
        .replace(
            "/run/gateway/scep-root-",
            &format!("/run/gateway/{host_id}/scep-root-"),
        );
    Journal::open(&config.gateway_directory.join("http"))?
        .replace(&format!("{host_id}.conf"), nginx.as_bytes())?;
    let routes = ingress_routes(decoded)?;
    Journal::open(&config.gateway_directory.join("routes"))?
        .replace(&format!("{host_id}.conf"), routes.as_bytes())?;
    ingress.replace(
        "nginx.conf",
        include_bytes!("../../../../deployment/nginx.conf"),
    )?;
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

fn ingress_routes(config: &crate::config::Config) -> Result<String> {
    let mut routes = BTreeMap::new();
    fn add(routes: &mut BTreeMap<String, String>, origin: &str, target: String) -> Result<()> {
        let origin = url::Url::parse(origin).map_err(|_| Error::Input)?;
        let hostname = origin.domain().ok_or(Error::Input)?;
        if origin.scheme() != "https"
            || origin.port_or_known_default() != Some(443)
            || !hostname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || routes.insert(hostname.to_owned(), target).is_some()
        {
            return Err(Error::Input);
        }
        Ok(())
    }
    add(&mut routes, &config.product_origin, "127.0.0.1:8445".into())?;
    if let Some(w) = &config.native_protocols.windows {
        for endpoint in [&w.enrollment, &w.management]
            .into_iter()
            .chain(&w.additional_management)
        {
            if endpoint.listen.ip().is_unspecified() {
                return Err(Error::Input);
            }
            add(&mut routes, &endpoint.origin, endpoint.listen.to_string())?;
        }
    }
    if let Some(a) = &config.native_protocols.apple {
        add(
            &mut routes,
            &a.management.origin,
            a.management.listen.to_string(),
        )?;
    }
    if let crate::agent_pki::Config::StepCa { endpoint, .. } = &config.agent_pki {
        if endpoint.listen.ip().is_unspecified() {
            return Err(Error::Input);
        }
        add(&mut routes, &endpoint.origin, endpoint.listen.to_string())?;
    }
    Ok(routes
        .into_iter()
        .map(|(host, target)| format!("{host} {target};\n"))
        .collect())
}
