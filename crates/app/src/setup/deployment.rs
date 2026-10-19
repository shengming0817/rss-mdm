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
    /// Docker-managed operator volume and bridge network, shared with the Compose installer.
    pub state_volume: String,
    pub network: String,
    pub publish_ip: std::net::IpAddr,
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
fn infrastructure_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(Error::Input);
    }
    Ok(())
}
fn volume_mount(_config: &Config, source: &Path, target: &str, readonly: bool) -> Result<Value> {
    let subpath = source
        .strip_prefix("/var/lib/rss-mdm")
        .map_err(|_| Error::Input)?;
    if subpath.as_os_str().is_empty()
        || subpath
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(Error::Input);
    }
    Ok(
        json!({"type":"volume","source":"operator-state","target":target,
        "read_only":readonly,"volume":{"nocopy":true,"subpath":subpath}}),
    )
}

fn network_origin(decoded: &crate::config::Config) -> Result<url::Url> {
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
    Ok(origin)
}

/// Apply an immutable, already prepared runtime snapshot and verify the actual HTTPS process.
/// Returns no success receipt until readyz reports the exact host, tenant, operation and revision.
pub async fn apply(directory: &Path, config: &Config, runtime: &Value) -> Result<Applied> {
    let decoded: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Input)?;
    let compiled = decoded.compile().map_err(|_| Error::Input)?;
    let decoded = &compiled.config;
    let origin = network_origin(decoded)?;
    infrastructure_name(&config.state_volume)?;
    infrastructure_name(&config.network)?;
    image_present(&config.server_image).await?;
    image_present(&config.gateway_image).await?;
    let certificate = crate::config::read(&config.certificate_file, 128 * 1024, false)
        .map_err(|_| Error::Input)?;
    let key =
        crate::config::read(&config.private_key_file, 32768, true).map_err(|_| Error::Input)?;
    let root =
        crate::config::read(&config.trust_file, 128 * 1024, false).map_err(|_| Error::Input)?;
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
    let journal = Journal::open(&stage)?;
    let server_journal = Journal::open(&stage.join("server"))?;
    let gateway_journal = Journal::open(&stage.join("gateway"))?;
    journal.secret(
        "source-runtime.json",
        &serde_json::to_vec(runtime).map_err(|_| Error::Input)?,
    )?;
    owner.save("requested-runtime.json", runtime)?;
    let mut projected = runtime.clone();
    let mut mounts = BTreeMap::new();
    project(&mut projected, &server_journal, &mut mounts, false)?;
    let bytes = serde_json::to_vec(&projected).map_err(|_| Error::Input)?;
    server_journal.secret("runtime.json", &bytes)?;
    gateway_journal.secret("tls.crt", &certificate)?;
    gateway_journal.secret("tls.key", &key)?;
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
    gateway_journal.secret("nginx.conf", gateway.as_bytes())?;
    let public = super::public_configuration::read(decoded).await?;
    gateway_journal.public(
        "ui.json",
        &serde_json::to_vec(&public.identity).map_err(|_| Error::Input)?,
    )?;
    gateway_journal.public(
        "mdm.json",
        &serde_json::to_vec(&public.mdm).map_err(|_| Error::Input)?,
    )?;
    let mut server_mounts = vec![volume_mount(
        config,
        &stage.join("server"),
        "/run/mdm",
        true,
    )?];
    if let Some(directory) = decoded
        .content
        .as_ref()
        .and_then(|v| v.storage.volume_directory())
    {
        let source = config.content_volume.as_ref().ok_or(Error::Input)?;
        // Both paths are inside Docker volumes. No daemon-side host path or host chown.
        let content = Journal::open(source)?;
        drop(content);
        server_mounts.push(volume_mount(
            config,
            source,
            directory.to_str().ok_or(Error::Input)?,
            false,
        )?);
    } else if config.content_volume.is_some() {
        return Err(Error::Conflict);
    }
    let mut ports = vec![
        json!({"target":8445,"published":origin.port_or_known_default().ok_or(Error::Input)?.to_string(),"host_ip":config.publish_ip.to_string()}),
    ];
    let mut native = Vec::new();
    if let Some(windows) = &decoded.native_protocols.windows {
        native.extend([windows.enrollment.listen, windows.management.listen]);
        native.extend(windows.additional_management.iter().map(|e| e.listen));
    }
    if let Some(apple) = &decoded.native_protocols.apple {
        native.push(apple.management.listen);
    }
    if let crate::agent_pki::Config::StepCa { endpoint, .. } = &decoded.agent_pki {
        native.push(endpoint.listen);
    }
    let mut used = std::collections::BTreeSet::from([8445, decoded.listen.port()]);
    for listen in native {
        if listen.ip().is_loopback() || !used.insert(listen.port()) {
            return Err(Error::Input);
        }
        ports.push(json!({"target":listen.port(),"published":listen.port().to_string(),"host_ip":config.publish_ip.to_string()}));
    }
    let compose = json!({"services":{
        "server":{"image":config.server_image,"user":"10001:10001","restart":"unless-stopped","read_only":true,"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"tmpfs":["/tmp:rw,noexec,nosuid,size=64m"],"volumes":server_mounts,"command":["serve","--config","/run/mdm/runtime.json"],"ports":ports,"networks":{"product":{"aliases":[hostname]}},"labels":{"rss.mdm.host":decoded.runtime_binding.host_id,"rss.mdm.operation":decoded.runtime_binding.operation_id}},
        "gateway":{"image":config.gateway_image,"user":"10001:10001","restart":"unless-stopped","network_mode":"service:server","depends_on":["server"],"read_only":true,"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"tmpfs":["/tmp:rw,noexec,nosuid,size=64m"],"entrypoint":["nginx"],"command":["-e","stderr","-c","/run/gateway/nginx.conf","-g","daemon off;"],"volumes":[volume_mount(config,&stage.join("gateway"),"/run/gateway",true)?],"labels":{"rss.mdm.host":decoded.runtime_binding.host_id,"rss.mdm.operation":decoded.runtime_binding.operation_id}}
    },"volumes":{"operator-state":{"external":true,"name":config.state_volume}},"networks":{"product":{"external":true,"name":config.network}}});
    let compose_path = journal.secret(
        "compose.json",
        &serde_json::to_vec(&compose).map_err(|_| Error::Input)?,
    )?;
    let path = compose_path.to_str().ok_or(Error::Input)?;
    // Replays validate all frozen bytes before observing the existing process.
    if previous.as_ref().is_some_and(|value| {
        matches(
            value,
            &decoded.runtime_binding,
            &decoded.identity.tenant_id,
            &decoded.identity.instance_id,
        )
    }) && let Ok(client) = probe_client(&root, &name, path, &decoded.product_origin).await
        && let Ok(current) = observe(
            &client.0,
            &client.1,
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
            &root,
            &name,
            path,
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
                        &root,
                        &name,
                        previous_path.to_str().ok_or(Error::Input)?,
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
        "--force-recreate",
        "--pull",
        "never",
    ])
    .await?;
    Ok(())
}
async fn wait_ready(
    root: &[u8],
    project: &str,
    compose: &str,
    origin: &str,
    binding: &Binding,
    tenant: &str,
    instance: &str,
) -> Result<Applied> {
    let (client, internal) = probe_client(root, project, compose, origin).await?;
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if let Ok(observed) =
                observe(&client, internal.as_str(), binding, tenant, instance).await
            {
                return observed;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .map_err(|_| Error::Storage)
}

async fn probe_client(
    root: &[u8],
    project: &str,
    compose: &str,
    origin: &str,
) -> Result<(reqwest::Client, String)> {
    let id = docker(&[
        "compose",
        "--env-file",
        "/dev/null",
        "-p",
        project,
        "-f",
        compose,
        "ps",
        "-q",
        "server",
    ])
    .await?;
    let id = std::str::from_utf8(&id).map_err(|_| Error::Storage)?.trim();
    let metadata = docker(&["inspect", id]).await?;
    let metadata: Value = serde_json::from_slice(&metadata).map_err(|_| Error::Storage)?;
    let networks = metadata[0]["NetworkSettings"]["Networks"]
        .as_object()
        .ok_or(Error::Storage)?;
    if networks.len() != 1 {
        return Err(Error::Input);
    }
    let address: std::net::IpAddr = networks.values().next().ok_or(Error::Storage)?["IPAddress"]
        .as_str()
        .ok_or(Error::Storage)?
        .parse()
        .map_err(|_| Error::Storage)?;
    let mut internal = url::Url::parse(origin).map_err(|_| Error::Input)?;
    let hostname = internal.host_str().ok_or(Error::Input)?.to_owned();
    internal.set_port(Some(8445)).map_err(|_| Error::Input)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8))
        .resolve(&hostname, std::net::SocketAddr::new(address, 8445))
        .add_root_certificate(reqwest::Certificate::from_pem(root).map_err(|_| Error::Input)?)
        .build()
        .map_err(|_| Error::Input)?;
    Ok((client, internal.as_str().trim_end_matches('/').to_owned()))
}

/// Resume/stop only the per-tenant projects recorded by this installation.
/// Compose owns the operator's process lifetime; the HTTP server has no Docker access.
pub async fn resume_hosts(input: &super::installation::Input) -> Result<()> {
    let mut failed = false;
    for (runtime, config) in recorded_hosts(input)? {
        if apply(&input.directory, &config, &runtime).await.is_err() {
            failed = true;
        }
    }
    if failed { Err(Error::Storage) } else { Ok(()) }
}
pub async fn stop_hosts(input: &super::installation::Input) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for (runtime, _) in recorded_hosts(input)? {
        let binding: Binding = serde_json::from_value(runtime["runtime_binding"].clone())
            .map_err(|_| Error::Corrupt)?;
        let name = format!("rss-mdm-{}", binding.host_id.simple());
        let path = input
            .directory
            .join(&name)
            .join(binding.operation_id.to_string())
            .join("compose.json");
        // A prepared candidate has no resources until its Compose input has been persisted.
        if !path.is_file() {
            continue;
        }
        tasks.spawn(async move {
            // Removing only this tenant's containers releases external volume/network references.
            // Docker-managed persistent data belongs to the outer Compose project and is retained.
            docker(&[
                "compose",
                "--env-file",
                "/dev/null",
                "-p",
                &name,
                "-f",
                path.to_str().ok_or(Error::Input)?,
                "down",
                "--timeout",
                "45",
            ])
            .await
            .map(|_| ())
        });
    }
    let mut failed = false;
    while let Some(result) = tasks.join_next().await {
        if !matches!(result, Ok(Ok(()))) {
            failed = true;
        }
    }
    if failed { Err(Error::Storage) } else { Ok(()) }
}
fn recorded_hosts(input: &super::installation::Input) -> Result<Vec<(Value, Config)>> {
    let installation = Journal::open(&input.directory)?;
    if installation
        .load::<Option<uuid::Uuid>>("backup-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }
    let reservations: BTreeMap<uuid::Uuid, usize> = installation
        .load("host-reservations.json")?
        .unwrap_or_default();
    let mut hosts = Vec::new();
    for entry in std::fs::read_dir(&input.directory).map_err(|_| Error::Storage)? {
        let entry = entry.map_err(|_| Error::Storage)?;
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("rss-mdm-"))
        {
            continue;
        }
        if !entry.file_type().map_err(|_| Error::Storage)?.is_dir() {
            return Err(Error::Input);
        }
        let journal = Journal::open(&entry.path())?;
        // A failed requested candidate must not block recovery of a confirmed prior runtime.
        let runtime = if let Some(applied) = journal.load::<Applied>("applied.json")? {
            let previous = Journal::open(&entry.path().join(applied.operation_id.to_string()))?;
            previous
                .load::<Value>("source-runtime.json")?
                .ok_or(Error::Corrupt)?
        } else {
            let Some(runtime) = journal.load::<Value>("requested-runtime.json")? else {
                continue;
            };
            runtime
        };
        let binding: Binding = serde_json::from_value(runtime["runtime_binding"].clone())
            .map_err(|_| Error::Corrupt)?;
        let config = reservations
            .get(&binding.host_id)
            .map(|index| {
                input
                    .additional_hosts
                    .get(*index)
                    .map(|slot| &slot.deployment)
                    .ok_or(Error::Conflict)
            })
            .transpose()?
            .unwrap_or(&input.deployment);
        hosts.push((
            runtime,
            serde_json::from_value(serde_json::to_value(config).map_err(|_| Error::Input)?)
                .map_err(|_| Error::Input)?,
        ));
    }
    Ok(hosts)
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
