//! Minimal current lifecycle state for downstream integration consumers.
use super::*;

pub async fn source_in(
    tx: &mut PgTransaction<'_>,
    source: SourceDefinition,
) -> Result<r::SoftwareSource> {
    storage::lock(tx).await?;
    let snapshot = source.snapshot()?;
    if storage::source(tx, &source.id, &source.revision)
        .await?
        .is_some()
    {
        return Err(Error::Conflict);
    }
    let lifecycle = Lifecycle {
        revision: 1,
        state: LifecycleState::Enabled,
        operation: uuid::Uuid::new_v4(),
        actor: "integration-fixture".into(),
        at: storage::now(tx).await?,
        digest: snapshot.sha256,
    };
    storage::save_source(tx, &source, &lifecycle).await?;
    Ok(snapshot)
}

/// Content pins are held by the caller until this transaction settles.
pub async fn enabled_in(
    tx: &mut PgTransaction<'_>,
    version: &r::Version,
    content: &dyn VerifiedContent,
) -> Result<()> {
    let reader = Reader::new(tx.tenant_id());
    reader.lock_in(tx).await?;
    if version.tenant() != tx.tenant_id() || content.resource_digest() != version.digest().bytes() {
        return Err(Error::Content);
    }
    let current = reader
        .version_in(tx, version.resource().as_str(), version.label().as_str())
        .await?;
    if current.digest() != version.digest()
        || storage::lifecycle(tx, version.resource().as_str(), version.label().as_str())
            .await?
            .is_some()
    {
        return Err(Error::Conflict);
    }
    reader.private_authoring_in(tx, version).await?;
    reader.check_sources(tx, version).await?;
    reader.dependencies(tx, version).await?;
    storage::freeze_materials(tx, version).await?;
    let lifecycle = Lifecycle {
        revision: 1,
        state: LifecycleState::Enabled,
        operation: uuid::Uuid::new_v4(),
        actor: "integration-fixture".into(),
        at: storage::now(tx).await?,
        digest: version.digest().bytes(),
    };
    storage::save_lifecycle(
        tx,
        version.resource().as_str(),
        version.label().as_str(),
        &lifecycle,
    )
    .await
}
