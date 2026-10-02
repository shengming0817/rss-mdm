//! Task signing authority, independently configured from artifact storage.
use crate::Error;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub private_key_file: PathBuf,
    pub key_id: String,
    pub trusted_keys: BTreeMap<String, String>,
}
pub(crate) fn open(
    config: &Config,
) -> Result<rss_mdm_execution_service::task_signing::Signer, Error> {
    let private = crate::config::read(&config.private_key_file, 4096, true)?;
    rss_mdm_execution_service::task_signing::Signer::from_bytes(
        &private,
        &config.key_id,
        &config.trusted_keys,
    )
    .map_err(Into::into)
}
