//! Tenant-scoped immutable content; PostgreSQL owns progress and exact material identities.
//! ref: sqlx sqlx-core/src/transaction.rs; aws-sdk-rust sdk/s3/src/operation/complete_multipart_upload/builders.rs (manifest freezing avoids assembly)
pub mod backup;
pub mod connections;
mod range;
pub use range::range;
mod backend;
mod bundle;
mod cleanup;
mod installer;
mod journal;
mod native;
pub use cleanup::Garbage;
mod budget;
mod protected;
mod reader;
mod upload;
pub use backend::{S3Storage, Storage};
pub use budget::UploadBudget;
pub use reader::{Pinned, Verified};
use rss_mdm_resource::Artifact;
use rss_request_context::{Clock, Deadline};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
pub use upload::{Binding, Purpose, ResourceBinding, Upload};
/// Trusted host configuration. A storage backend is required; old directory-only input is rejected.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub storage: Storage,
    pub imports: std::collections::BTreeMap<
        String,
        Vec<rss_mdm_software_service::publication::ArtifactOrigin>,
    >,
    pub max_artifact_bytes: u64,
    pub max_temporary_bytes: u64,
    pub max_uploads: usize,
    pub transfer_seconds: u64,
    pub retention_seconds: u64,

    pub max_bundle_entries: usize,
    pub max_expansion_ratio: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    #[default]
    Artifact,
    NativeConfiguration,
}
impl StorageClass {
    fn protection_domain(self) -> &'static str {
        match self {
            Self::Artifact => "content.artifact",
            Self::NativeConfiguration => "content.native-configuration",
        }
    }
    fn protected(self) -> bool {
        self != Self::Artifact
    }
}
#[derive(Clone)]
pub struct Store {
    protection: Arc<rss_mdm_native_protection::Protector>,
    tenant: rss_request_context::TenantId,
    pub config: Config,
    transfers: Arc<Semaphore>,
    timer: Arc<dyn Clock>,
    backend: backend::Backend,
    pool: sqlx::PgPool,
    cleanup_tasks: tokio_util::task::TaskTracker,
}
fn storage() -> Error {
    Error::Storage
}
fn invariant() -> Error {
    Error::Invariant
}
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn regular(path: &Path) -> Result<(), Error> {
    if !fs::symlink_metadata(path).map_err(|_| storage())?.is_file() {
        return Err(invariant());
    }
    Ok(())
}
fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
}
fn sync_dir(path: &Path) -> Result<(), Error> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| storage())
}
impl Store {
    /// Host owns the pool lifetime. No filesystem progress or implicit provider fallback.
    pub async fn open(
        protection: Arc<rss_mdm_native_protection::Protector>,
        config: &Config,
        tenant: &str,
        timer: Arc<dyn Clock>,
        pool: sqlx::PgPool,
    ) -> Result<Arc<Self>, Error> {
        let tenant =
            rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Configuration)?;
        if config.max_artifact_bytes == 0
            || config.max_artifact_bytes > 1_099_511_627_776
            || config.max_temporary_bytes < config.max_artifact_bytes
            || config.max_temporary_bytes > 17_592_186_044_416
            || !(1..=64).contains(&config.max_uploads)
            || !(1..=86400).contains(&config.transfer_seconds)
            || !(config.transfer_seconds..=604800).contains(&config.retention_seconds)
            || !(1..=4096).contains(&config.max_bundle_entries)
            || !(1..=1000).contains(&config.max_expansion_ratio)
            || config.imports.len() > 16
        {
            return Err(Error::Configuration);
        }
        for (source, origins) in &config.imports {
            rss_mdm_resource::Id::new(source).map_err(|_| Error::Configuration)?;
            rss_mdm_software_service::publication::ArtifactReader::new(
                origins.clone(),
                config.max_artifact_bytes,
                std::time::Duration::from_secs(config.transfer_seconds.min(3600)),
            )
            .map_err(|_| Error::Configuration)?;
        }
        let connection = if let Storage::S3(s3) = &config.storage {
            let mut tx = pool.begin().await.map_err(|_| storage())?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *tx)
                .await
                .map_err(|_| storage())?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','3000',true)").bind(tenant.to_string()).execute(&mut *tx).await.map_err(|_|storage())?;
            let value = connections::load(&mut tx, tenant, s3.revision, &protection).await?;
            tx.rollback().await.map_err(|_| storage())?;
            Some(Arc::new(value))
        } else {
            None
        };
        let backend = backend::Backend::open(
            &config.storage,
            tenant,
            timer.clone(),
            config.transfer_seconds,
            connection,
        )
        .await?;
        let store = Arc::new(Self {
            protection,
            tenant,
            config: config.clone(),
            transfers: Arc::new(Semaphore::new(config.max_uploads)),
            timer,
            backend,
            pool,
            cleanup_tasks: tokio_util::task::TaskTracker::new(),
        });
        store.journal_admit().await?;
        Ok(store)
    }
    pub async fn close(&self) {
        self.cleanup_tasks.close();
        self.cleanup_tasks.wait().await;
        self.pool.close().await;
    }
    fn deadline(&self) -> Result<Deadline, Error> {
        Deadline::from_timeout(
            self.timer.as_ref(),
            std::time::Duration::from_secs(self.config.transfer_seconds),
        )
        .map_err(|_| storage())
    }
}
#[derive(Clone, Copy, Debug, thiserror::Error, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    #[error("invalid content configuration")]
    Configuration,
    #[error("malformed content request")]
    Malformed,
    #[error("content operation conflict")]
    Conflict,
    #[error("content storage unavailable")]
    Storage,
    #[error("content invariant violated")]
    Invariant,
    #[serde(rename = "content_metadata")]
    #[error("invalid upload metadata")]
    Metadata,
    #[error("content deadline exceeded")]
    Deadline,
    #[error("content write or commit outcome unknown")]
    CommitUnknown,
    #[error("content cleanup failed")]
    Cleanup,
}

pub mod bindings;
pub mod event;

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub const ADMISSION_SQL: &str = include_str!("admission.sql");

pub mod service;
mod transaction;

/// Content operations consumed through software-owned ports.
pub mod software;

#[cfg(test)]
#[path = "../tests/unit.rs"]
mod tests;

#[cfg(feature = "integration")]
pub mod fixture;
