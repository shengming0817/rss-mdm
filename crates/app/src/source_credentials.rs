//! Host-owned principal/secret/audit implementation for the software service.
use rss_mdm_software_service::Credentials;
use std::{collections::BTreeMap, path::PathBuf};
pub(crate) struct SourceCredentials {
    tenant: rss_request_context::TenantId,
    source: String,
    values: BTreeMap<String, zeroize::Zeroizing<String>>,
}
impl SourceCredentials {
    pub(crate) fn load(
        tenant: rss_request_context::TenantId,
        source: &str,
        files: &BTreeMap<String, PathBuf>,
    ) -> Result<Self, crate::Error> {
        let mut values = BTreeMap::new();
        for (key, path) in files {
            values.insert(key.clone(), crate::config::secret(path)?);
        }
        Ok(Self {
            tenant,
            source: source.into(),
            values,
        })
    }
}
impl Credentials for SourceCredentials {
    fn winget(
        &self,
        tenant: rss_request_context::TenantId,
        source: &str,
        reference: &str,
    ) -> rss_mdm_software_service::publication::Result<rss_mdm_winget_source::WriteAccess> {
        use rss_mdm_software_service::publication::Error;
        if tenant != self.tenant || source != self.source {
            return Err(Error::Identity);
        }
        rss_mdm_winget_source::WriteAccess::new(
            tenant,
            source,
            reference,
            self.values.get(reference).ok_or(Error::Identity)?,
        )
        .map_err(|_| Error::Identity)
    }
}
