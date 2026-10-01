//! Trusted local operator policy for the fixture example, not device authentication.
use rss_mdm_inventory::{CollectionDefinition, DATASET, Source, builtin};
use rss_observation::{Access, Authority, Error, ErrorKind, Scope};

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
                scope == &self.scope
                    && definition().coverage().is_ok_and(|v| c == &v)
                    && scope.dataset().as_str() == DATASET
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

/// This fixture publishes an explicit collector just as a production collection owner does.
pub fn definition() -> CollectionDefinition {
    CollectionDefinition::new(
        DATASET,
        "fixture-v1",
        Source::AgentBuiltin,
        builtin::fields()
            .into_iter()
            .filter(|f| [builtin::MODEL, builtin::OS_VERSION].contains(&f.key))
            .collect(),
    )
    .expect("fixture definition")
}
