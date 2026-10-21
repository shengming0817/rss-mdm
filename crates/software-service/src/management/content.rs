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
/// Immutable upload coordinates supplied by software preparation, never by a manifest.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareUpload {
    pub operation_id: Uuid,
    pub filename: String,
    pub length: u64,
    pub sha256: [u8; 32],
}
/// Observed file facts; absence of a fact is not a claim about platform trust.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallerFacts {
    pub format: r::SoftwareFormat,
    pub version: Option<String>,
    pub architectures: Vec<r::Architecture>,
    pub bundle_id: Option<String>,
}
pub struct InspectedUpload<D> {
    pub facts: InstallerFacts,
    pub artifact: r::SoftwareArtifact,
    pub filename: String,
    pub _pin: D,
}
pub trait ManagementContentPort: ContentPort {
    type Download: Send;
    type StagedImport: Send;
    type ImportEvidence: ImportedContent;
    fn prepare_upload(&self, input: &PrepareUpload, resource: &str, upload: Uuid, actor: &str)
        -> impl Future<Output = Result<serde_json::Value, Error>> + Send;
    fn inspect_upload(&self, upload: Uuid, actor: &str, resource: &str)
        -> impl Future<Output = Result<InspectedUpload<Self::Download>, Error>> + Send;

    fn inspect_installer(&self, artifact: &r::Artifact, filename: &str)
        -> impl Future<Output = Result<InstallerFacts, Error>> + Send;
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
