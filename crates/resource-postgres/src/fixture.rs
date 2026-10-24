//! Integration prerequisites encoded by the storage owner, without publication side effects.
use crate::{STORAGE, codec, core::*};
use rss_contract::Timepoint;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

/// Insert one new active version and its reference indexes in the caller's tenant transaction.
/// Rejects occupied identities; does not forge receipts, audit records, or publication events.
pub async fn active_version_in(
    tx: &mut PgTransaction<'_>,
    version: Version,
    at: Timepoint,
) -> Result<(), PgError> {
    if version.tenant() != tx.tenant_id() {
        return Err(STORAGE.fault("fixture::tenant"));
    }
    let mut resource = Resource::new(version.tenant(), version.resource().clone(), version.kind());
    crate::error::decode_domain("fixture::insert", resource.insert(version.clone(), at))?;
    crate::error::decode_domain("fixture::activate", resource.activate(version.label(), at))?;
    STORAGE
        .write(
            tx,
            version.resource().as_str(),
            None,
            3,
            codec::header(&resource)?,
        )
        .await?;
    STORAGE
        .freeze(
            tx,
            version.resource().as_str(),
            "version",
            version.label().as_str(),
            codec::version(&version)?,
        )
        .await?;
    crate::artifacts::insert(tx, &version).await
}

/// Insert a current draft without activation, for publication consumers that own activation.
pub async fn draft_version_in(tx: &mut PgTransaction<'_>, version: Version, at: Timepoint) -> Result<(), PgError> {
    if version.tenant() != tx.tenant_id() { return Err(STORAGE.fault("fixture::tenant")); }
    let mut resource = Resource::new(version.tenant(), version.resource().clone(), version.kind());
    crate::error::decode_domain("fixture::insert", resource.insert(version.clone(), at))?;
    STORAGE.write(tx, version.resource().as_str(), None, 2, codec::header(&resource)?).await?;
    STORAGE.freeze(tx, version.resource().as_str(), "version", version.label().as_str(), codec::version(&version)?).await?;
    crate::artifacts::insert(tx, &version).await
}
