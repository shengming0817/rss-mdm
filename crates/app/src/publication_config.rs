use rss_mdm_software_service::publication as service;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceConfig {
    pub(crate) name: String,
    pub(crate) credentials: std::collections::BTreeMap<String, std::path::PathBuf>,
    pub(crate) rings: service::RingSources,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) database: crate::config::Database,
    pub(crate) sources: Vec<SourceConfig>,
}
impl Config {
    /// This product owns every served output URI. Import origins are configured separately.
    pub(crate) fn validate_hosted(&self, origin: &str) -> Result<(), crate::Error> {
        let invalid = || crate::Error::Configuration(crate::ConfigIssue::Publication);
        let mut names = std::collections::BTreeSet::new();
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
            let mut references = std::collections::BTreeSet::new();
            let mut winget = 0;
            for (name, ring) in [
                ("test", &source.rings.test),
                ("pilot", &source.rings.pilot),
                ("production", &source.rings.production),
            ] {
                let (base, artifacts) = match ring {
                    service::SourceConfig::Winget(config) => {
                        winget += 1;
                        (&config.base, &config.artifacts_base)
                    }
                    service::SourceConfig::Brew(config) => {
                        references.insert(&config.credential_reference);
                        (&config.base, &config.artifacts_base)
                    }
                };
                if base != &format!("{origin}/software/native/sources/{}/{name}/", source.name)
                    || artifacts
                        != &format!(
                            "{origin}/software/native/sources/{}/artifacts/",
                            source.name
                        )
                {
                    return Err(invalid());
                }
            }
            if winget != 0 && winget != 3 {
                return Err(invalid());
            }
            if source
                .credentials
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
                != references
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
