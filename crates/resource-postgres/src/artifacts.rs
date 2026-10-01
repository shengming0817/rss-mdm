//! Content cleanup queries a Resource-owned index, never an upload-history approximation.
use crate::{STORAGE, core::*};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use std::collections::BTreeSet;
pub(crate) async fn insert(tx: &mut PgTransaction<'_>, version: &Version) -> Result<(), PgError> {
    let mut artifacts = BTreeSet::new();
    for variant in version.variants() {
        match variant.declaration() {
            Declaration::Software { definition } => {
                for artifact in definition.materials() {
                    artifacts.insert((artifact.sha256, artifact.length));
                }
            }
            other => {
                let a = other.artifact();
                artifacts.insert((a.digest().bytes(), a.length()));
            }
        }
    }
    for (sha256, length) in artifacts {
        lock(tx, Digest::from_bytes(sha256)).await?;
        let tenant = tx.tenant_id().to_string();
        let owner = version.resource().as_str().to_owned();
        let label = version.label().as_str().to_owned();
        let length = i64::try_from(length).map_err(|_| STORAGE.fault("artifacts::length"))?;
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO mdm_resource.artifact_refs VALUES($1::uuid,$2,$3,$4,$5,false)",
                )
                .bind(tenant)
                .bind(owner)
                .bind(label)
                .bind(sha256.to_vec())
                .bind(length)
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .await?;
    }
    Ok(())
}
pub(crate) async fn archive(
    tx: &mut PgTransaction<'_>,
    owner: &Id,
    version: &Id,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let owner = owner.as_str().to_owned();
    let version = version.as_str().to_owned();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_resource.artifact_refs SET archived=true WHERE tenant_id=$1::uuid AND owner=$2 AND version=$3").bind(tenant).bind(owner).bind(version).execute(c).await?;Ok(())})).await?;
    Ok(())
}
async fn lock(tx: &mut PgTransaction<'_>, digest: Digest) -> Result<(), PgError> {
    let key: String = digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    STORAGE.lock(tx, "artifact", &key).await
}
/// True while any non-archived resource version in the borrowed tenant references these bytes.
/// Acquires the same tenant/digest transaction lock as reference insertion. The host must
/// retain this transaction through final file removal and exclude live file readers/writers. Resource archival
/// continues to require the complete external approval/publication/execution reference check.
pub async fn artifact_referenced_in(
    tx: &mut PgTransaction<'_>,
    digest: Digest,
) -> Result<bool, PgError> {
    lock(tx, digest).await?;
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_resource.artifact_refs WHERE tenant_id=$1::uuid AND sha256=$2 AND NOT archived)").bind(tenant).bind(digest.bytes().to_vec()).fetch_one(c).await})).await
}
