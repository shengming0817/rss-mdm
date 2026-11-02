//! Original issuer and offline-root material admission for cold product recovery.
use rss_mdm_install_support::maintenance::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub purpose: rss_mdm_agent_wire::pki::Purpose,
    pub issuer: String,
    pub configuration_file: PathBuf,
    pub online_directory: PathBuf,
    pub offline_directory: PathBuf,
    pub root_private_key_file: PathBuf,
    pub root_password_file: PathBuf,
}
fn ca_file(authority: &Authority, value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.starts_with(&authority.online_directory)
        || path.canonicalize().map_err(|_| Error::Input)? != path
    {
        return Err(Error::Input);
    }
    Ok(path)
}
pub fn verify(authority: &Authority) -> Result<()> {
    let configuration = &authority.configuration_file;
    if !configuration.starts_with(&authority.online_directory)
        || !authority
            .root_private_key_file
            .starts_with(&authority.offline_directory)
        || !authority
            .root_password_file
            .starts_with(&authority.offline_directory)
    {
        return Err(Error::Input);
    }
    let config: Value = serde_json::from_slice(
        &rss_mdm_install_support::files::read(configuration, 1024 * 1024, false)
            .map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)?;
    let issuer = openssl::x509::X509::from_pem(
        &rss_mdm_install_support::files::read(
            &ca_file(authority, config["crt"].as_str().ok_or(Error::Input)?)?,
            131072,
            false,
        )
        .map_err(|_| Error::Input)?,
    )
    .map_err(|_| Error::Input)?;
    if rss_mdm_device_trust::digest(&issuer.to_der().map_err(|_| Error::Input)?) != authority.issuer
    {
        return Err(Error::Conflict);
    }
    let password = rss_mdm_install_support::files::secret(&authority.root_password_file)
        .map_err(|_| Error::Input)?;
    let key = rss_mdm_install_support::files::read(&authority.root_private_key_file, 32768, true)
        .map_err(|_| Error::Input)?;
    let key = openssl::pkey::PKey::private_key_from_pem_passphrase(&key, password.as_bytes())
        .map_err(|_| Error::Input)?;
    let roots = match &config["root"] {
        Value::String(root) => vec![root.as_str()],
        Value::Array(roots) => roots
            .iter()
            .map(|r| r.as_str().ok_or(Error::Input))
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(Error::Input),
    };
    let mut matched = 0;
    for root in roots {
        let root = openssl::x509::X509::from_pem(
            &rss_mdm_install_support::files::read(&ca_file(authority, root)?, 131072, false)
                .map_err(|_| Error::Input)?,
        )
        .map_err(|_| Error::Input)?;
        let public = root.public_key().map_err(|_| Error::Input)?;
        if public.public_eq(&key)
            && issuer.verify(&public).map_err(|_| Error::Input)?
            && issuer.issuer_name().to_der().map_err(|_| Error::Input)?
                == root.subject_name().to_der().map_err(|_| Error::Input)?
        {
            matched += 1;
        }
    }
    if matched != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
