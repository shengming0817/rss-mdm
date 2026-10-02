//! Only the file operations actually consumed by software management.
use super::{Error, Fault};
use crate::catalog::ContentPort;
use rss_mdm_resource as r;
use rss_transactional_messaging_postgres::PgTransaction;
use std::future::Future;
use uuid::Uuid;
pub struct StageImport<'a> {
    pub upload: Uuid,
    pub actor: &'a str,
    pub version: &'a r::Version,
    pub variant: &'a str,
    pub platform: r::Platform,
    pub architecture: r::Architecture,
    pub source: &'a r::SoftwareSource,
    pub artifact: &'a r::SoftwareArtifact,
    pub bytes: &'a [u8],
}
pub trait ManagementContentPort: ContentPort {
    type Download: Send;
    type StagedImport: Send;
    type ImportEvidence: ImportedContent;
    fn verify_artifact(
        &self,
        artifact: &r::Artifact,
    ) -> impl Future<Output = Result<Self::Download, Error>> + Send;
    fn stage_import(
        &self,
        input: StageImport<'_>,
    ) -> impl Future<Output = Result<Self::StagedImport, Error>> + Send;
    /// Pin all staged originals under one transfer permit through transaction settlement.
    fn pin_imports(
        &self,
        staged: Vec<Self::StagedImport>,
    ) -> impl Future<Output = Result<Self::ImportEvidence, Error>> + Send;
}
/// Pins live until the caller settles the borrowed binding transaction.
pub trait ImportedContent: Send + Sync {
    fn bind_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
    ) -> impl Future<Output = Result<(), Fault>> + Send + 'a;
}
