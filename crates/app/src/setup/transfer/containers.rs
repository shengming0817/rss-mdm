//! 固定 V4 容器的停写与文件定位；不执行容器内任意命令。
use crate::setup::{Error, Result, deployment::docker, local::Journal};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

#[derive(Serialize, Deserialize)]
pub(super) struct Mount {
    source: PathBuf,
    destination: PathBuf,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Container {
    pub id: String,
    pub mounts: Vec<Mount>,
    pub runtime: Value,
}
fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}
impl Container {
    pub fn resolve(&self, path: &Path) -> Result<PathBuf> {
        if !absolute(path) {
            return Err(Error::Input);
        }
        let mount = self
            .mounts
            .iter()
            .filter(|m| path.starts_with(&m.destination))
            .max_by_key(|m| m.destination.components().count())
            .ok_or(Error::Input)?;
        let relative = path
            .strip_prefix(&mount.destination)
            .map_err(|_| Error::Input)?;
        let source = if relative.as_os_str().is_empty() {
            mount.source.clone()
        } else {
            mount.source.join(relative)
        };
        let canonical = source.canonicalize().map_err(|_| Error::Input)?;
        if canonical != source || !canonical.starts_with(&mount.source) {
            return Err(Error::Input);
        }
        Ok(source)
    }
    pub fn copy_inputs(&self, journal: &Journal, runtime: &mut Value) -> Result<()> {
        fn file(
            owner: &Container,
            journal: &Journal,
            value: &mut Value,
            private: bool,
        ) -> Result<()> {
            use sha2::{Digest, Sha256};
            let original = Path::new(value.as_str().ok_or(Error::Input)?);
            let source = owner.resolve(original)?;
            let bytes =
                crate::config::read(&source, 1024 * 1024, private).map_err(|_| Error::Input)?;
            let name = format!(
                "input-{:x}",
                Sha256::digest(source.as_os_str().as_encoded_bytes())
            );
            *value = serde_json::json!(journal.secret(&name, &bytes)?);
            Ok(())
        }
        match runtime {
            Value::Object(values) => {
                for (name, value) in values {
                    if name.ends_with("_file") && value.is_string() {
                        let public = matches!(
                            name.as_str(),
                            "ca_file"
                                | "tls_root_file"
                                | "trust_file"
                                | "certificate_file"
                                | "profile_certificate_file"
                                | "apns_certificate_file"
                                | "private_ca_file"
                        );
                        file(self, journal, value, !public)?;
                    } else if name == "key_files" {
                        for value in value.as_object_mut().ok_or(Error::Input)?.values_mut() {
                            file(self, journal, value, true)?;
                        }
                    } else {
                        self.copy_inputs(journal, value)?;
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.copy_inputs(journal, value)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
}
pub(super) async fn inspect(id: &str, image: &str) -> Result<Container> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Input);
    }
    let expected = docker(&["image", "inspect", "--format", "{{.Id}}", image]).await?;
    let actual = docker(&["container", "inspect", "--format", "{{.Image}}", id]).await?;
    if expected != actual {
        return Err(Error::Conflict);
    }
    let command: Vec<String> = serde_json::from_slice(
        &docker(&[
            "container",
            "inspect",
            "--format",
            "{{json .Config.Cmd}}",
            id,
        ])
        .await?,
    )
    .map_err(|_| Error::Input)?;
    if command.len() != 3 || command[0] != "serve" || command[1] != "--config" {
        return Err(Error::Input);
    }
    let mounts: Vec<Value> = serde_json::from_slice(
        &docker(&["container", "inspect", "--format", "{{json .Mounts}}", id]).await?,
    )
    .map_err(|_| Error::Input)?;
    let mut bindings = Vec::new();
    for mount in mounts {
        if !matches!(mount["Type"].as_str(), Some("bind" | "volume")) {
            continue;
        }
        let source = PathBuf::from(mount["Source"].as_str().ok_or(Error::Input)?);
        let destination = PathBuf::from(mount["Destination"].as_str().ok_or(Error::Input)?);
        if !absolute(&source)
            || !absolute(&destination)
            || source.canonicalize().map_err(|_| Error::Input)? != source
        {
            return Err(Error::Input);
        }
        bindings.push(Mount {
            source,
            destination,
        });
    }
    let mut container = Container {
        id: id.into(),
        mounts: bindings,
        runtime: Value::Null,
    };
    let path = container.resolve(Path::new(&command[2]))?;
    let bytes = crate::config::read(&path, 1024 * 1024, true).map_err(|_| Error::Input)?;
    container.runtime = serde_json::from_slice(&bytes).map_err(|_| Error::Input)?;
    Ok(container)
}
pub(super) async fn stop(containers: &[Container]) -> Result<()> {
    // 先关闭旧容器的自动重启；中断恢复保持停写，不自动回到旧运行权威。
    for container in containers {
        docker(&["container", "update", "--restart=no", &container.id]).await?;
        docker(&["container", "stop", "--time", "60", &container.id]).await?;
        let running = docker(&[
            "container",
            "inspect",
            "--format",
            "{{.State.Running}}",
            &container.id,
        ])
        .await?;
        if running != b"false\n" {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
