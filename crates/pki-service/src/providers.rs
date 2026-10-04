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
impl Providers {
    pub fn new(entries: Vec<Provider>) -> Result<Self, Error> {
        if entries.len() > 48 {
            return Err(Error::Configuration);
        }
        for (i, p) in entries.iter().enumerate() {
            if let Some(endpoint) = &p.scep_url {
                let url = url::Url::parse(endpoint).map_err(|_| Error::Configuration)?;
                if p.purpose != Purpose::Apple
                    || url.origin() != p.client.origin.origin()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !url.path().starts_with("/scep/")
                    || url.path().len() <= 6
                {
                    return Err(Error::Configuration);
                }
            } else if p.purpose == Purpose::Apple {
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
    pub fn entries(&self) -> &[Provider] {
        &self.entries
    }
}
