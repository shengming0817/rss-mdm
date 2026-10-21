//! Content cleanup queries a Resource-owned index, never an upload-history approximation.
use crate::{STORAGE, core::*};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use std::collections::BTreeSet;
pub(crate) async fn insert(tx: &mut PgTransaction<'_>, version: &Version) -> Result<(), PgError> {
    let mut artifacts = BTreeSet::new();
    let mut fields = BTreeSet::new();
    let mut templates = BTreeSet::new();
    for variant in version.variants() {
        if let Declaration::Script { definition, .. } = variant.declaration()
            && let ScriptPurpose::Collection { mappings, .. } = &definition.spec().purpose
        {
            fields.extend(mappings.keys().cloned());
        }
        if let Declaration::NativeCollection { definition, .. } = variant.declaration() {
            fields.extend(definition.spec().mappings.keys().cloned());
        }
        if let Declaration::AgentCollection { definition, .. } = variant.declaration() {
            fields.extend(definition.spec().mappings.keys().cloned());
        }
        if let Declaration::TelemetryProfile { definition, .. } = variant.declaration() {
            fields.extend(
                definition
                    .spec()
                    .fields
                    .iter()
                    .map(|f| f.key.as_str().to_owned()),
            );
            templates.insert((
                definition.spec().template.resource.clone(),
                definition.spec().template.version.clone(),
            ));
        }
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
    let telemetry = !templates.is_empty();
    for (target, target_version) in templates {
        let tenant = tx.tenant_id().to_string();
        let owner = version.resource().as_str().to_owned();
        let version = version.label().as_str().to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO mdm_resource.profile_refs VALUES($1::uuid,$2,$3,$4,$5,false)",
                )
                .bind(tenant)
                .bind(owner)
                .bind(version)
                .bind(target)
                .bind(target_version)
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .await?;
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
    let tenant = tx.tenant_id().to_string();
    let owner = version.resource().as_str().to_owned();
    let version = version.label().as_str().to_owned();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_resource.field_refs SELECT $1::uuid,$2,$3,f,false,$5 FROM unnest($4::text[]) f").bind(tenant).bind(owner).bind(version).bind(fields.into_iter().collect::<Vec<_>>()).bind(telemetry).execute(c).await?;Ok(())
    })).await?;
    Ok(())
}
pub(crate) async fn archive(
    tx: &mut PgTransaction<'_>,
    owner: &Id,
    version: &Id,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    let profile_owner = owner.as_str().to_owned();
    let profile_version = version.as_str().to_owned();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_resource.profile_refs SET archived=true WHERE tenant_id=$1::uuid AND owner=$2 AND version=$3")
            .bind(tenant).bind(profile_owner).bind(profile_version).execute(c).await?;
        Ok(())
    })).await?;
    let tenant = tx.tenant_id().to_string();
    let owner = owner.as_str().to_owned();
    let version = version.as_str().to_owned();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_resource.field_refs SET archived=true WHERE tenant_id=$1::uuid AND owner=$2 AND version=$3").bind(&tenant).bind(&owner).bind(&version).execute(&mut *c).await?;sqlx::query("UPDATE mdm_resource.artifact_refs SET archived=true WHERE tenant_id=$1::uuid AND owner=$2 AND version=$3").bind(tenant).bind(owner).bind(version).execute(c).await?;Ok(())})).await?;
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

/// Active profiles that prevent archival of an exact collection template.
pub async fn profile_references_in(
    tx: &mut PgTransaction<'_>,
    resource: &str,
    version: &str,
) -> Result<u64, PgError> {
    let tenant = tx.tenant_id().to_string();
    let resource = resource.to_owned();
    let version = version.to_owned();
    let count: i64 = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT count(*) FROM mdm_resource.profile_refs WHERE tenant_id=$1::uuid AND target=$2 AND target_version=$3 AND NOT archived")
            .bind(tenant).bind(resource).bind(version).fetch_one(c).await
    })).await?;
    u64::try_from(count).map_err(|_| STORAGE.fault("profile_refs::count"))
}

/// Active references block retirement; archived references explain retained definitions only.
pub async fn field_reference_details_in(
    tx: &mut PgTransaction<'_>,
    field: &str,
) -> Result<(i64, i64, i64), PgError> {
    let tenant = tx.tenant_id().to_string();
    let field = field.to_owned();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as("SELECT count(*) FILTER(WHERE NOT archived AND NOT telemetry),count(*) FILTER(WHERE NOT archived AND telemetry),count(*) FILTER(WHERE archived) FROM mdm_resource.field_refs WHERE tenant_id=$1::uuid AND field=$2")
            .bind(tenant).bind(field).fetch_one(c).await
    })).await
}
