//! F01 product fixture policy; this is not a device authenticator.
use rss_observation::{Access, Authority, Batch, Coverage, Error, ErrorKind, Id, Scope};

pub const DATASET: &str = "inventory";
pub const JOURNAL: &str = "mdm.observation.v1";
pub const GENERATION: &str = "inventory-v1";

pub fn coverage() -> Coverage {
    let id = |s| Id::new(s).expect("static valid identity");
    Coverage::new(id("device-basics"), id("1"), id("model-os"), id("utf8-v1"))
}

pub struct FixtureAuthority {
    scope: Scope,
}
impl FixtureAuthority {
    pub fn new(scope: Scope) -> Self {
        Self { scope }
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}
impl Authority for FixtureAuthority {
    fn authorize(&self, access: Access<'_>) -> Result<(), Error> {
        let allowed = match access {
            Access::Read { scope } | Access::Activate { scope } => scope == &self.scope,
            Access::Submit { scope, coverage: c } => {
                scope == &self.scope && c == &coverage() && scope.dataset().as_str() == DATASET
            }
            // This local operator owns journal processing for the configured tenant.
            Access::ReadJournal { tenant } => tenant == self.scope.tenant(),
        };
        if allowed {
            Ok(())
        } else {
            Err(ErrorKind::Unauthorized.into())
        }
    }
}

pub fn validate(batch: &Batch) -> Result<(), Error> {
    if batch.coverage() != &coverage() {
        return Err(ErrorKind::InvalidInput.into());
    }
    for change in batch.body().changes() {
        if !matches!(change.key().as_str(), "device.model" | "device.os.version") {
            return Err(ErrorKind::InvalidInput.into());
        }
        if let Some(value) = change.value() {
            let text =
                std::str::from_utf8(value).map_err(|_| Error::from(ErrorKind::InvalidInput))?;
            if text.trim().is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
                return Err(ErrorKind::InvalidInput.into());
            }
        }
    }
    Ok(())
}
