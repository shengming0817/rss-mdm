//! ref: systemd 262 man/systemd.service.xml and man/systemctl.xml.
//! Linux deployment supervisor. Only the installation operator can install this unit.
use super::{Error, Result, installation::Input, local::Journal};
use std::{path::Path, time::Duration};

fn unit(executable: &Path, input: &Path, name: &str) -> Result<String> {
    let path = |value: &Path| -> Result<String> {
        let value = value.to_str().ok_or(Error::Input)?;
        if !value.starts_with('/')
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        {
            return Err(Error::Input);
        }
        Ok(value.to_owned())
    };
    Ok(format!(
        "[Unit]\nDescription=RSS MDM tenant deployment operator {name}\nAfter=network-online.target docker.service\nRequires=docker.service\n\n[Service]\nType=simple\nUser=root\nUMask=0077\nExecStart={} provision-hosts --config {}\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=15\n\n[Install]\nWantedBy=multi-user.target\n",
        path(executable)?,
        path(input)?
    ))
}
async fn systemctl(arguments: &[&str]) -> Result<()> {
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("systemctl")
            .args(arguments)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| Error::Storage)?
    .map_err(|_| Error::Storage)?;
    if !result.status.success() {
        return Err(Error::Storage);
    }
    Ok(())
}
pub(super) async fn install(journal: &Journal, input: &Input, instance: uuid::Uuid) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(Error::Input);
    }
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    if std::fs::metadata(&input.directory)
        .map_err(|_| Error::Storage)?
        .uid()
        != 0
    {
        return Err(Error::Input);
    }
    // A root service must not execute a mutable binary from an operator's download directory.
    let source = std::env::current_exe().map_err(|_| Error::Storage)?;
    let binary =
        crate::config::read(&source, 256 * 1024 * 1024, false).map_err(|_| Error::Storage)?;
    let executable = journal.path("rss-mdm-deployer")?;
    if executable.exists() {
        let metadata = std::fs::symlink_metadata(&executable).map_err(|_| Error::Storage)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(Error::Input);
        }
        let existing = crate::config::read(&executable, 256 * 1024 * 1024, true)
            .map_err(|_| Error::Storage)?;
        if *existing != *binary {
            return Err(Error::Conflict);
        }
    } else {
        let temporary = journal.path(&format!("binary-{}", uuid::Uuid::new_v4()))?;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o700)
            .open(&temporary)
            .map_err(|_| Error::Storage)?;
        file.write_all(&binary)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Storage)?;
        std::fs::rename(&temporary, &executable).map_err(|_| Error::Storage)?;
        std::fs::File::open(&input.directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Storage)?;
    }
    activate(journal, input, instance).await
}
/// The sealed recovery archive owns the restored deployer binary. Do not substitute
/// the recovery command's executable or require both release versions to match.
pub(super) async fn restore(journal: &Journal, input: &Input, instance: uuid::Uuid) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let executable = journal.path("rss-mdm-deployer")?;
    let metadata = std::fs::symlink_metadata(&executable).map_err(|_| Error::Corrupt)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.permissions().mode() & 0o100 == 0
    {
        return Err(Error::Corrupt);
    }
    activate(journal, input, instance).await
}
async fn activate(journal: &Journal, input: &Input, instance: uuid::Uuid) -> Result<()> {
    let name = format!("rss-mdm-deployer-{}.service", instance.simple());
    let executable = journal.path("rss-mdm-deployer")?;
    let input_path = journal.path("deployer-input.json")?;
    let contents = unit(&executable, &input_path, &name)?;
    // The operator may rewrite the protected JSON when allocating host capacity.
    // Preserve the exact validated configuration, independent of JSON whitespace.
    if let Some(existing) = journal.load::<Input>("deployer-input.json")? {
        if serde_json::to_value(&existing).map_err(|_| Error::Corrupt)?
            != serde_json::to_value(input).map_err(|_| Error::Input)?
        {
            return Err(Error::Conflict);
        }
    } else {
        journal.secret(
            "deployer-input.json",
            &serde_json::to_vec(input).map_err(|_| Error::Input)?,
        )?;
    }
    let unit_path = journal.secret(&name, contents.as_bytes())?;
    systemctl(&["link", unit_path.to_str().ok_or(Error::Input)?]).await?;
    systemctl(&["daemon-reload"]).await?;
    systemctl(&["enable", "--now", &name]).await?;
    systemctl(&["is-active", "--quiet", &name]).await
}

#[cfg(test)]
#[path = "../../tests/setup/supervisor.rs"]
mod tests;
