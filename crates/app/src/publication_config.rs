use rss_mdm_software_service::publication as service;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceConfig {
    pub(crate) name: String,
    pub(crate) credentials: std::collections::BTreeMap<String, std::path::PathBuf>,
    pub(crate) target: service::SourceConfig,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) database: crate::config::Database,
    pub(crate) sources: Vec<SourceConfig>,
}
impl Config {
    pub(crate) fn validate_hosted(&self, origin: &str) -> Result<(), crate::Error> {
        let invalid = || crate::Error::Configuration(crate::ConfigIssue::Publication);
        let mut names = std::collections::BTreeSet::new();
        let mut physical = std::collections::BTreeSet::new();
        for source in &self.sources {
            if source.name.is_empty()
                || source.name.len() > 128
                || !source
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || !names.insert(&source.name)
            {
                return Err(invalid());
            }
            let (base, artifacts, reference, identity) = match &source.target {
                service::SourceConfig::Winget(c) => {
                    (&c.base, &c.artifacts_base, None, c.base.clone())
                }
                service::SourceConfig::Brew(c) => (
                    &c.base,
                    &c.artifacts_base,
                    Some(&c.credential_reference),
                    c.repository
                        .canonicalize()
                        .map_err(|_| invalid())?
                        .to_string_lossy()
                        .into_owned(),
                ),
            };
            if base != &format!("{origin}/api/v1/software/native/sources/{}/", source.name)
                || artifacts
                    != &format!(
                        "{origin}/api/v1/software/native/sources/{}/artifacts/",
                        source.name
                    )
                || !physical.insert(identity)
            {
                return Err(invalid());
            }
            if source
                .credentials
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
                != reference.into_iter().collect()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "../tests/config/publication_unit.rs"]
mod tests;
