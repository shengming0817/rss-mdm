//! 停写后的 PostgreSQL 原样归档；数据库备份不是内容卷、对象版本和密钥的替代品。
use crate::setup::{Error, Result, local::Journal};
use serde::{Deserialize, Serialize};
use std::{io::Read, os::unix::fs::OpenOptionsExt, path::Path};
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::setup) struct DatabaseBackup {
    pub sha256: String,
    pub bytes: u64,
}
fn database_digest(path: &Path) -> Result<DatabaseBackup> {
    let value = file_digest(path)?;
    if value.bytes == 0 {
        return Err(Error::Corrupt);
    }
    Ok(value)
}

/// The archive and restore client major must match the server, including PG16 telemetry.
async fn client(database: &crate::config::Database, restore: bool) -> Result<&'static str> {
    use sqlx::Connection;
    let mut connection =
        sqlx::PgConnection::connect_with(&database.options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
    let major: i32 =
        sqlx::query_scalar("SELECT current_setting('server_version_num')::integer/10000")
            .fetch_one(&mut connection)
            .await
            .map_err(|_| Error::Storage)?;
    connection.close().await.map_err(|_| Error::Storage)?;
    let tool = match (major, restore) {
        (16, false) => "pg_dump16",
        (16, true) => "pg_restore16",
        (17, false) => "pg_dump",
        (17, true) => "pg_restore",
        _ => return Err(Error::Input),
    };
    let version = tokio::time::timeout(
        std::time::Duration::from_secs(6),
        tokio::process::Command::new(tool)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| Error::Storage)?
    .map_err(|_| Error::Storage)?;
    if !version.status.success()
        || !String::from_utf8_lossy(&version.stdout).contains(&format!("(PostgreSQL) {major}."))
    {
        return Err(Error::Input);
    }
    Ok(tool)
}

pub(in crate::setup) async fn capture(
    journal: &Journal,
    database: &crate::config::Database,
) -> Result<DatabaseBackup> {
    let path = journal.path("database.dump")?;
    if let Some(previous) = journal.load::<DatabaseBackup>("database-backup.json")? {
        let actual = database_digest(&path)?;
        if previous.sha256 != actual.sha256 || previous.bytes != actual.bytes {
            return Err(Error::Corrupt);
        }
        return Ok(previous);
    }
    let stage = journal.path(&format!("database-{}.pending", uuid::Uuid::new_v4()))?;
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&stage)
        .map_err(|_| Error::Storage)?;
    let password = crate::config::secret(&database.password_file).map_err(|_| Error::Input)?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3600),
        tokio::process::Command::new(client(database, false).await?)
            .args([
                "--format=custom",
                "--exclude-table=public.mdm_restore_operation",
                "--no-password",
                "--host",
                &database.host,
                "--port",
                &database.port.to_string(),
                "--username",
                &database.user,
                "--dbname",
                &database.name,
            ])
            .env_remove("PGSERVICE")
            .env_remove("PGSERVICEFILE")
            .env_remove("PGOPTIONS")
            .env("PGPASSWORD", password.as_str())
            .env("PGSSLMODE", "verify-full")
            .env("PGSSLROOTCERT", &database.ca_file)
            .env("PGCONNECT_TIMEOUT", "5")
            .stdin(std::process::Stdio::null())
            .stdout(file)
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await;
    if !matches!(result,Ok(Ok(status)) if status.success()) {
        return Err(Error::Storage);
    }
    std::fs::File::open(&stage)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::Storage)?;
    let receipt = database_digest(&stage)?;
    std::fs::rename(&stage, &path).map_err(|_| Error::Storage)?;
    std::fs::File::open(path.parent().ok_or(Error::Input)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::Storage)?;
    journal.save("database-backup.json", &receipt)?;
    Ok(receipt)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileRecord {
    relative: std::path::PathBuf,
    sha256: String,
    bytes: u64,
}
pub(in crate::setup) fn file_digest(path: &Path) -> Result<DatabaseBackup> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Error::Storage)?;
    let before = file.metadata().map_err(|_| Error::Storage)?;
    if !before.is_file() {
        return Err(Error::Input);
    }
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut bytes = [0u8; 65536];
    loop {
        let n = file.read(&mut bytes).map_err(|_| Error::Storage)?;
        if n == 0 {
            break;
        }
        digest.update(&bytes[..n]);
        size = size.checked_add(n as u64).ok_or(Error::Corrupt)?;
    }
    if size != before.len()
        || before.modified().ok() != file.metadata().map_err(|_| Error::Storage)?.modified().ok()
    {
        return Err(Error::Conflict);
    }
    Ok(DatabaseBackup {
        sha256: format!("{:x}", digest.finalize()),
        bytes: size,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::setup) struct Bundle {
    pub format: u32,
    pub operation: uuid::Uuid,
    files: Vec<FileRecord>,
}
/// 清单只包含停写快照及其原保管文件，不包含仍会推进的操作检查点。
pub(in crate::setup) fn seal(journal: &Journal, operation: uuid::Uuid) -> Result<String> {
    let name = "backup-manifest.json";
    if let Some(bundle) = journal.load::<Bundle>(name)? {
        if bundle.operation != operation {
            return Err(Error::Conflict);
        }
        let hash = file_digest(&journal.path(name)?)?.sha256;
        verify(journal, &hash)?;
        return Ok(hash);
    }
    let root = journal
        .path("restore-source.json")?
        .parent()
        .ok_or(Error::Input)?
        .to_owned();
    let mut queue = vec![std::path::PathBuf::new()];
    let mut files = Vec::new();
    while let Some(relative) = queue.pop() {
        if relative.components().count() > 32 {
            return Err(Error::Input);
        }
        for entry in std::fs::read_dir(root.join(&relative)).map_err(|_| Error::Storage)? {
            let entry = entry.map_err(|_| Error::Storage)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error::Input)?;
            if name == "install.lock"
                || name.ends_with(".pending")
                || (relative.as_os_str().is_empty()
                    && matches!(
                        name,
                        "backup-manifest.json"
                            | "backup-progress.json"
                            | "restore-progress.json"
                            | "restore-request.json"
                    ))
            {
                continue;
            }
            let path = relative.join(name);
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| Error::Storage)?;
            if metadata.is_dir() {
                queue.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err(Error::Input);
            }
            let digest = file_digest(&entry.path())?;
            files.push(FileRecord {
                relative: path,
                sha256: digest.sha256,
                bytes: digest.bytes,
            });
        }
    }
    files.sort_by(|a, b| a.relative.cmp(&b.relative));
    journal.secret(
        name,
        &serde_json::to_vec(&Bundle {
            format: 1,
            operation,
            files,
        })
        .map_err(|_| Error::Corrupt)?,
    )?;
    Ok(file_digest(&journal.path(name)?)?.sha256)
}
/// 期望摘要必须来自独立保存的备份回执，不能从待恢复目录自我取信。
pub(in crate::setup) fn verify(journal: &Journal, expected: &str) -> Result<Bundle> {
    if expected.len() != 64
        || file_digest(&journal.path("backup-manifest.json")?)?.sha256 != expected
    {
        return Err(Error::Corrupt);
    }
    let bundle: Bundle = journal
        .load("backup-manifest.json")?
        .ok_or(Error::Corrupt)?;
    if bundle.format != 1 || bundle.files.is_empty() {
        return Err(Error::Corrupt);
    }
    let root = journal
        .path("backup-manifest.json")?
        .parent()
        .ok_or(Error::Input)?
        .to_owned();
    let mut seen = std::collections::BTreeSet::new();
    for record in &bundle.files {
        if record.relative.as_os_str().is_empty()
            || !record
                .relative
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            || !seen.insert(&record.relative)
        {
            return Err(Error::Corrupt);
        }
        let mut path = root.clone();
        for part in record.relative.components() {
            path.push(part);
            if std::fs::symlink_metadata(&path)
                .map_err(|_| Error::Storage)?
                .file_type()
                .is_symlink()
            {
                return Err(Error::Corrupt);
            }
        }
        let actual = file_digest(&path)?;
        if actual.sha256 != record.sha256 || actual.bytes != record.bytes {
            return Err(Error::Corrupt);
        }
    }
    for required in [
        "database.dump",
        "database-backup.json",
        "restore-source.json",
        "ledger-checkpoints.json",
    ] {
        if !bundle
            .files
            .iter()
            .any(|f| f.relative == Path::new(required))
        {
            return Err(Error::Corrupt);
        }
    }
    Ok(bundle)
}

pub(in crate::setup) async fn restore_database(
    journal: &Journal,
    database: &crate::config::Database,
) -> Result<()> {
    let expected: DatabaseBackup = journal
        .load("database-backup.json")?
        .ok_or(Error::Corrupt)?;
    let path = journal.path("database.dump")?;
    let actual = database_digest(&path)?;
    if expected.sha256 != actual.sha256 || expected.bytes != actual.bytes {
        return Err(Error::Corrupt);
    }
    let password = crate::config::secret(&database.password_file).map_err(|_| Error::Input)?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3600),
        tokio::process::Command::new(client(database, true).await?)
            .args([
                "--single-transaction",
                "--exit-on-error",
                "--no-password",
                "--host",
                &database.host,
                "--port",
                &database.port.to_string(),
                "--username",
                &database.user,
                "--dbname",
                &database.name,
            ])
            .arg(path)
            .env_remove("PGSERVICE")
            .env_remove("PGSERVICEFILE")
            .env_remove("PGOPTIONS")
            .env("PGPASSWORD", password.as_str())
            .env("PGSSLMODE", "verify-full")
            .env("PGSSLROOTCERT", &database.ca_file)
            .env("PGCONNECT_TIMEOUT", "5")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await;
    if !matches!(result,Ok(Ok(status)) if status.success()) {
        return Err(Error::Storage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backup_manifest_rejects_changed_material_and_symlink_ancestors() {
        let temp = tempfile::tempdir().unwrap();
        let journal = Journal::open(&temp.path().canonicalize().unwrap().join("bundle")).unwrap();
        for name in [
            "database.dump",
            "database-backup.json",
            "restore-source.json",
            "ledger-checkpoints.json",
        ] {
            journal.secret(name, b"original").unwrap();
        }
        let material = Journal::open(&journal.path("source-host").unwrap()).unwrap();
        material.secret("ledger.key", b"fixed-ledger-key").unwrap();
        let operation = uuid::Uuid::new_v4();
        let hash = seal(&journal, operation).unwrap();
        assert!(verify(&journal, &hash).is_ok());
        assert_eq!(seal(&journal, operation).unwrap(), hash);
        assert!(verify(&journal, &"0".repeat(64)).is_err());
        std::fs::write(material.path("ledger.key").unwrap(), b"replacement").unwrap();
        assert!(matches!(verify(&journal, &hash), Err(Error::Corrupt)));
        std::fs::write(material.path("ledger.key").unwrap(), b"fixed-ledger-key").unwrap();
        assert!(verify(&journal, &hash).is_ok());
        drop(material);
        let directory = journal.path("source-host").unwrap();
        let moved = temp.path().join("moved");
        std::fs::rename(&directory, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &directory).unwrap();
        assert!(matches!(verify(&journal, &hash), Err(Error::Corrupt)));
    }
}
