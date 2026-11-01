//! Agent installation freezes an explicitly published release, never deployment pins.
use crate::deployment::authorization::context::AuthorizedPrincipal;
use crate::deployment::{Error, Inputs, transaction::*};
use crate::installation::package::FrozenInstall;
use rss_mdm_policy::{SoftwareTarget, schedule::Schedule};
use rss_transactional_messaging_postgres::PgTransaction;
use std::collections::BTreeMap;
use uuid::Uuid;
impl Inputs {
    fn installation_inputs(&self) -> crate::installation::inputs::Inputs {
        crate::installation::inputs::Inputs {
            runtime: self.runtime.clone(),
            tenant: self.tenant,
            bootstrap_configured: self.materials.bootstrap_configured,
            admission: self.materials.agent_installation.clone(),
        }
    }

    pub(crate) async fn freeze_agent_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        snapshot: &crate::deployment::authorization::Snapshot,
        releases: &BTreeMap<SoftwareTarget, Uuid>,
        schedule: &Schedule,
        lifetime: u32,
    ) -> Result<FrozenInstall> {
        self.installation_inputs()
            .freeze_in(tx, proof, snapshot, releases, schedule, lifetime)
            .await
            .map_err(Into::into)
    }
}
pub(crate) fn publication_error(error: crate::management::Error) -> Error {
    use crate::management::Error as E;
    match error {
        E::Forbidden => Error::Forbidden,
        E::ResourceMissing => Error::NotFound,
        E::Malformed => Error::Malformed,
        E::Conflict => Error::Conflict,
        _ => Error::Unavailable(crate::deployment::Failure::SoftwareCatalogStorage),
    }
}
