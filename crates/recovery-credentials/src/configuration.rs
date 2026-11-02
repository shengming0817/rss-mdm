//! Configuration belongs to the host; material encryption and lifecycle belong to the product owner.
use crate::Error;
use crate::{KeyRing, Protection, Recipient};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub active_key: String,
    pub key_files: BTreeMap<String, PathBuf>,
    pub active_recipient: String,
    pub recipients: Vec<RecipientConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientConfig {
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}
impl Config {
    pub fn open(&self) -> Result<Arc<Protection>, Error> {
        let bad = || Error::Malformed;
        let keys = self
            .key_files
            .iter()
            .map(|(id, path)| {
                Ok((
                    id.clone(),
                    rss_mdm_install_support::files::read(path, 32, true).map_err(|_| bad())?,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let keys = KeyRing::new(self.active_key.clone(), keys).map_err(|_| bad())?;
        let recipients = self
            .recipients
            .iter()
            .map(|r| {
                Recipient::from_pem(
                    &rss_mdm_install_support::files::read(&r.certificate_file, 65536, false)
                        .map_err(|_| bad())?,
                    &rss_mdm_install_support::files::read(&r.private_key_file, 65536, true)
                        .map_err(|_| bad())?,
                )
                .map_err(|_| bad())
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Protection::new(keys, self.active_recipient.clone(), recipients)
            .map(Arc::new)
            .map_err(|_| bad())
    }
}
