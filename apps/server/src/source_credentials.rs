//! Host-owned principal/secret/audit implementation for the software service.
use rss_mdm_software_service::Credentials;
use std::{collections::BTreeMap, path::PathBuf};
pub(crate) struct SourceCredentials {
    source: String,
    values: BTreeMap<uuid::Uuid, BTreeMap<String, zeroize::Zeroizing<String>>>,
}
impl SourceCredentials {
    pub(crate) fn load(
        source: &str,
        files: &BTreeMap<uuid::Uuid, BTreeMap<String, PathBuf>>,
    ) -> Result<Self, crate::Error> {
        let mut values = BTreeMap::new();
        for (tenant, files) in files {
            let mut credentials = BTreeMap::new();
            for (key, path) in files {
                credentials.insert(key.clone(), crate::config::secret(path)?);
            }
            values.insert(*tenant, credentials);
        }
        Ok(Self {
            source: source.into(),
            values,
        })
    }
}
impl Credentials for SourceCredentials {
    fn brew_read(
        &self,
        tenant: rss_request_context::TenantId,
        source: &str,
        reference: &str,
    ) -> rss_mdm_software_service::publication::Result<rss_mdm_software_service::BrewReadAccess>
    {
        use rss_mdm_software_service::publication::Error;
        if source != self.source {
            return Err(Error::Identity);
        }
        rss_mdm_software_service::BrewReadAccess::new(
            tenant,
            source,
            self.values
                .get(&uuid::Uuid::parse_str(&tenant.to_string()).map_err(|_| Error::Identity)?)
                .and_then(|values| values.get(reference))
                .ok_or(Error::Identity)?,
        )
        .map_err(|_| Error::Identity)
    }
}
