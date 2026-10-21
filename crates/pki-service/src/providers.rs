//! Explicit issuer generation routing. Prepared providers are configured before activation.
use crate::{Error, StepCa};
use rss_mdm_agent_wire::pki::Purpose;
use std::sync::Arc;
pub struct Provider {
    pub purpose: Purpose,
    pub issuer: String,
    pub client: Arc<StepCa>,
    pub scep_url: Option<String>,
}
pub struct Providers {
    entries: Vec<Provider>,
}
/// Device-facing SCEP address, independent of the private CA API origin.
pub fn scep_endpoint(value: &str) -> Result<url::Url, Error> {
    let url = url::Url::parse(value).map_err(|_| Error::Configuration)?;
    let name = url
        .path()
        .strip_prefix("/scep/")
        .ok_or(Error::Configuration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(Error::Configuration);
    }
    Ok(url)
}
impl Providers {
    pub fn new(entries: Vec<Provider>) -> Result<Self, Error> {
        if entries.len() > 48 {
            return Err(Error::Configuration);
        }
        for (i, p) in entries.iter().enumerate() {
            if let Some(endpoint) = &p.scep_url {
                if !matches!(p.purpose, Purpose::Apple | Purpose::AgentBootstrap) {
                    return Err(Error::Configuration);
                }
                scep_endpoint(endpoint)?;
            } else if matches!(p.purpose, Purpose::Apple | Purpose::AgentBootstrap) {
                return Err(Error::Configuration);
            }
            if p.issuer.len() != 64
                || !p
                    .issuer
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || entries[..i]
                    .iter()
                    .any(|q| q.purpose == p.purpose && q.issuer == p.issuer)
            {
                return Err(Error::Configuration);
            }
        }
        Ok(Self { entries })
    }
    pub fn get(&self, purpose: Purpose, issuer: &str) -> Result<&Arc<StepCa>, Error> {
        self.entries
            .iter()
            .find(|p| p.purpose == purpose && p.issuer == issuer)
            .map(|p| &p.client)
            .ok_or(Error::Configuration)
    }
    pub fn scep(&self, issuer: &str) -> Result<&str, Error> {
        self.entries
            .iter()
            .find(|p| p.purpose == Purpose::Apple && p.issuer == issuer)
            .and_then(|p| p.scep_url.as_deref())
            .ok_or(Error::Configuration)
    }
    pub fn bootstrap_scep(&self, issuer: &str) -> Result<&str, Error> {
        self.entries
            .iter()
            .find(|p| p.purpose == Purpose::AgentBootstrap && p.issuer == issuer)
            .and_then(|p| p.scep_url.as_deref())
            .ok_or(Error::Configuration)
    }
    pub fn entries(&self) -> &[Provider] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_scep_address_has_no_private_ca_origin_dependency() {
        let url = scep_endpoint("https://mdm.example.test/scep/rss").unwrap();
        assert_eq!(url.path(), "/scep/rss");
        assert_ne!(url.origin().ascii_serialization(), "https://step-ca:9000");
        for value in [
            "http://mdm.example.test/scep/rss",
            "https://u:p@mdm.example.test/scep/rss",
            "https://mdm.example.test/scep/rss?operation=GetCACert",
            "https://mdm.example.test/scep/rss#x",
            "https://mdm.example.test/scep/",
            "https://mdm.example.test/scep/rss/admin",
            "https://mdm.example.test/scep/rss%2fadmin",
            "https://mdm.example.test/admin",
        ] {
            assert!(scep_endpoint(value).is_err(), "{value}");
        }
    }
}
