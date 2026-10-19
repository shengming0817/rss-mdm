//! Local Docker Compose application. No command, image, path or maintenance capability is accepted by HTTP.
use super::{Error, Result, host::Binding, local::Journal};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Fixed local OCI image ID or a repository digest, never a mutable tag.
    pub server_image: String,
    pub gateway_image: String,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub trust_file: PathBuf,
    pub content_volume: Option<PathBuf>,
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
fn image(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .or_else(|| value.rsplit_once("@sha256:").map(|v| v.1))
        .ok_or(Error::Input)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || value.chars().any(char::is_whitespace)
    {
        return Err(Error::Input);
    }
    Ok(())
}
pub(super) async fn docker(args: &[&str]) -> Result<Vec<u8>> {
    let output = tokio::time::timeout(
        Duration::from_secs(90),
        tokio::process::Command::new("docker")
            .args(args)
            .env_remove("DOCKER_CONTEXT")
            .env("DOCKER_HOST", "unix:///var/run/docker.sock")
            .env_remove("COMPOSE_FILE")
            .env_remove("COMPOSE_PROJECT_NAME")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| Error::Storage)?
    .map_err(|_| Error::Storage)?;
    // Docker diagnostics may contain input paths or secrets; expose only the closed error above.
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        return Err(Error::Storage);
    }
    Ok(output.stdout)
}
async fn image_present(id: &str) -> Result<()> {
    image(id)?;
    let output = docker(&["image", "inspect", "--format", "{{.Id}}", id]).await?;
    let actual = std::str::from_utf8(&output)
        .map_err(|_| Error::Input)?
        .trim();
    image(actual)?;
    if id.starts_with("sha256:") && actual != id {
        return Err(Error::Conflict);
    }
    Ok(())
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
async fn runtime_owner(paths: impl Iterator<Item = PathBuf>) -> Result<()> {
    // The dedicated deployment operator owns this action. The server never receives chown or Docker authority.
    for path in paths {
        let status = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("chown")
                .arg("10001:10001")
                .arg(&path)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| Error::Storage)?
        .map_err(|_| Error::Storage)?;
        if !status.status.success() {
            return Err(Error::Storage);
        }
    }
    Ok(())
}
/// Apply an immutable, already prepared runtime snapshot and verify the actual HTTPS process.
/// Returns no success receipt until readyz reports the exact host, tenant, operation and revision.
pub async fn apply(directory: &Path, config: &Config, runtime: &Value) -> Result<Applied> {
    let decoded: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Input)?;
    let compiled = decoded.compile().map_err(|_| Error::Input)?;
    let decoded = &compiled.config;
    if !decoded.listen.ip().is_loopback() || decoded.trusted_gateway != decoded.listen.ip() {
        return Err(Error::Input);
    }
    let origin = url::Url::parse(&decoded.product_origin).map_err(|_| Error::Input)?;
    if origin.scheme() != "https"
        || origin.origin().ascii_serialization() != decoded.product_origin
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err(Error::Input);
    }
    let gateway_port = origin.port_or_known_default().ok_or(Error::Input)?;
    let mut ports = vec![decoded.listen.port()];
    if let Some(windows) = &decoded.native_protocols.windows {
        ports.extend([
            windows.enrollment.listen.port(),
            windows.management.listen.port(),
        ]);
        ports.extend(
            windows
                .additional_management
                .iter()
                .map(|e| e.listen.port()),
        );
    }
    if let Some(apple) = &decoded.native_protocols.apple {
        ports.push(apple.management.listen.port());
    }
    if let crate::agent_pki::Config::StepCa { endpoint, .. } = &decoded.agent_pki {
        ports.push(endpoint.listen.port());
    }
    if ports.iter().any(|port| *port == 0 || *port == gateway_port) {
        return Err(Error::Input);
    }
    image_present(&config.server_image).await?;
    image_present(&config.gateway_image).await?;
    let certificate = crate::config::read(&config.certificate_file, 128 * 1024, false)
        .map_err(|_| Error::Input)?;
    let key =
        crate::config::read(&config.private_key_file, 32768, true).map_err(|_| Error::Input)?;
    let root =
        crate::config::read(&config.trust_file, 128 * 1024, false).map_err(|_| Error::Input)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8))
        .add_root_certificate(reqwest::Certificate::from_pem(&root).map_err(|_| Error::Input)?)
        .build()
        .map_err(|_| Error::Input)?;
    let name = format!("rss-mdm-{}", decoded.runtime_binding.host_id.simple());
    let host_root = directory.join(&name);
    let owner = Journal::open(&host_root)?;
    let previous = owner.load::<Applied>("applied.json")?;
    if let Some(previous) = &previous {
        admit_successor(
            previous,
            &decoded.runtime_binding,
            &decoded.identity.tenant_id,
            &decoded.identity.instance_id,
        )?;
    }
    let stage = host_root.join(decoded.runtime_binding.operation_id.to_string());
    let journal = Journal::projection(&stage)?;
    journal.secret(
        "source-runtime.json",
        &serde_json::to_vec(runtime).map_err(|_| Error::Input)?,
    )?;
    owner.save("requested-runtime.json", runtime)?;
    let mut projected = runtime.clone();
    let mut mounts = BTreeMap::new();
    project(&mut projected, &journal, &mut mounts, false)?;
    let bytes = serde_json::to_vec(&projected).map_err(|_| Error::Input)?;
    let runtime_path = journal.secret("runtime.json", &bytes)?;
    runtime_owner(
        mounts
            .values()
            .cloned()
            .chain(std::iter::once(runtime_path.clone())),
    )
    .await?;
    let certificate_path = journal.secret("tls.crt", &certificate)?;
    let key_path = journal.secret("tls.key", &key)?;
    let authority = origin[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
    let hostname = origin.host_str().ok_or(Error::Input)?;
    if !hostname
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return Err(Error::Input);
    }
    let gateway = include_str!("../../../../deployment/nginx.conf")
        .replace("127.0.0.1:8081", &decoded.listen.to_string())
        .replace(
            "listen 443 ssl;",
            &format!(
                "listen {} ssl;",
                origin.port_or_known_default().ok_or(Error::Input)?
            ),
        )
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
        .replace("/run/config/mdm.json", "/run/gateway/mdm.json")
        .replace(
            "location / { try_files $uri $uri/ /index.html; }",
            "location / { return 404; }",
        );
    let gateway_path = journal.secret("nginx.conf", gateway.as_bytes())?;
    let public = super::public_configuration::read(decoded).await?;
    let ui_path = journal.public(
        "ui.json",
        &serde_json::to_vec(&public.identity).map_err(|_| Error::Input)?,
    )?;
    let mdm_path = journal.public(
        "mdm.json",
        &serde_json::to_vec(&public.mdm).map_err(|_| Error::Input)?,
    )?;
    let mount = |source: &Path, target: String| json!({"type":"bind","source":source,"target":target,"read_only":true,"bind":{"create_host_path":false}});
    let mut server_mounts = mounts
        .iter()
        .map(|(name, path)| mount(path, format!("/run/mdm/{name}")))
        .collect::<Vec<_>>();
    server_mounts.push(mount(&runtime_path, "/run/mdm/runtime.json".into()));
    if let Some(directory) = decoded
        .content
        .as_ref()
        .and_then(|v| v.storage.volume_directory())
    {
        use std::os::unix::fs::MetadataExt;
        let source = config.content_volume.as_ref().ok_or(Error::Input)?;
        let meta = std::fs::symlink_metadata(source).map_err(|_| Error::Input)?;
        if !source.is_absolute()
            || source.canonicalize().map_err(|_| Error::Input)? != *source
            || !meta.is_dir()
            || meta.uid() != 10001
            || meta.mode() & 0o077 != 0
            || !directory.is_absolute()
            || directory == Path::new("/")
        {
            return Err(Error::Input);
        }
        server_mounts.push(json!({"type":"bind","source":source,"target":directory,"read_only":false,"bind":{"create_host_path":false}}));
    } else if config.content_volume.is_some() {
        return Err(Error::Conflict);
    }

    let compose = json!({"services":{
        "server":{"image":config.server_image,"network_mode":"host","user":"10001:10001","read_only":true,"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"tmpfs":["/tmp:rw,noexec,nosuid,size=64m"],"volumes":server_mounts,"command":["serve","--config","/run/mdm/runtime.json"],"labels":{"rss.mdm.host":decoded.runtime_binding.host_id,"rss.mdm.operation":decoded.runtime_binding.operation_id}},
        "gateway":{"image":config.gateway_image,"network_mode":"host","read_only":true,"cap_drop":["ALL"],"cap_add":["NET_BIND_SERVICE","SETUID","SETGID","CHOWN"],"security_opt":["no-new-privileges:true"],"tmpfs":["/tmp:rw,noexec,nosuid,size=64m"],"entrypoint":["nginx"],"command":["-e","stderr","-c","/run/gateway/nginx.conf","-g","daemon off;"],"volumes":[mount(&gateway_path,"/run/gateway/nginx.conf".into()),mount(&certificate_path,"/run/gateway/tls.crt".into()),mount(&key_path,"/run/gateway/tls.key".into()),mount(&ui_path,"/run/gateway/ui.json".into()),mount(&mdm_path,"/run/gateway/mdm.json".into())],"labels":{"rss.mdm.host":decoded.runtime_binding.host_id,"rss.mdm.operation":decoded.runtime_binding.operation_id}}
    }});
    let compose_path = journal.secret(
        "compose.json",
        &serde_json::to_vec(&compose).map_err(|_| Error::Input)?,
    )?;
    let path = compose_path.to_str().ok_or(Error::Input)?;
    // Verify every immutable projected input before accepting an idempotent replay.
    if previous.as_ref().is_some_and(|value| {
        matches(
            value,
            &decoded.runtime_binding,
            &decoded.identity.tenant_id,
            &decoded.identity.instance_id,
        )
    }) && let Ok(current) = observe(
        &client,
        &decoded.product_origin,
        &decoded.runtime_binding,
        &decoded.identity.tenant_id,
        &decoded.identity.instance_id,
    )
    .await
    {
        owner.save("applied.json", &current)?;
        return Ok(current);
    }
    let applied = async {
        compose_up(&name, path).await?;
        wait_ready(
            &client,
            &decoded.product_origin,
            &decoded.runtime_binding,
            &decoded.identity.tenant_id,
            &decoded.identity.instance_id,
        )
        .await
    }
    .await;
    match applied {
        Ok(observed) => {
            owner.save("applied.json", &observed)?;
            Ok(observed)
        }
        Err(error) => {
            // Restoring an earlier immutable snapshot is an operator action; it never advances
            // applied revision and never reports the rejected candidate as healthy.
            if let Some(previous) = previous
                && previous.operation_id != decoded.runtime_binding.operation_id
            {
                let previous_path = host_root
                    .join(previous.operation_id.to_string())
                    .join("compose.json");
                let restored = async {
                    compose_up(&name, previous_path.to_str().ok_or(Error::Input)?).await?;
                    let binding = Binding {
                        host_id: previous.host_id,
                        operation_id: previous.operation_id,
                        revision: previous.revision,
                        material_digest: previous.material_digest.clone(),
                    };
                    wait_ready(
                        &client,
                        &decoded.product_origin,
                        &binding,
                        &previous.tenant_id,
                        &previous.instance_id,
                    )
                    .await
                }
                .await;
                if let Ok(observed) = restored {
                    owner.save("applied.json", &observed)?;
                }
            }
            Err(error)
        }
    }
}
fn admit_successor(
    previous: &Applied,
    binding: &Binding,
    tenant: &str,
    instance: &str,
) -> Result<()> {
    if previous.host_id != binding.host_id
        || previous.tenant_id != tenant
        || previous.instance_id != instance
        || binding.revision < previous.revision
        || (binding.revision == previous.revision && !matches(previous, binding, tenant, instance))
        || (binding.revision > previous.revision && binding.operation_id == previous.operation_id)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
async fn compose_up(name: &str, path: &str) -> Result<()> {
    docker(&[
        "compose",
        "--env-file",
        "/dev/null",
        "-p",
        name,
        "-f",
        path,
        "up",
        "-d",
        "--no-build",
        "--pull",
        "never",
    ])
    .await?;
    Ok(())
}
async fn wait_ready(
    client: &reqwest::Client,
    origin: &str,
    binding: &Binding,
    tenant: &str,
    instance: &str,
) -> Result<Applied> {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if let Ok(observed) = observe(client, origin, binding, tenant, instance).await {
                return observed;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .map_err(|_| Error::Storage)
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
#[path = "../../tests/setup/deployment.rs"]
mod tests;
