use rss_mdm_software_service::publication as service;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceConfig {
    pub(crate) name: String,
    pub(crate) credentials: std::collections::BTreeMap<String, std::path::PathBuf>,
    pub(crate) rings: service::RingSources,
    pub(crate) artifacts: Vec<service::ArtifactOrigin>,
    pub(crate) max_artifact_bytes: u64,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) database: crate::config::Database,
    pub(crate) sources: Vec<SourceConfig>,
}
