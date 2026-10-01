//! Catalog and frozen collection contracts borrow the caller's tenant transaction.
use anyhow::{Result, ensure};
use rss_mdm_inventory::{
    Catalog, CollectionDefinition, FieldDefinition, FieldKey, Source, builtin,
};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use std::collections::BTreeMap;

/// Load the single published catalog at a committed input watermark.
/// Builtin seed definitions and tenant-authored definitions enter the same validator.
pub async fn catalog_at_in(
    c: &mut PgConnection,
    tenant: TenantId,
    watermark: i64,
) -> Result<Catalog> {
    crate::reader::assert_tenant(c, tenant).await?;
    ensure!(watermark >= 0, "invalid catalog watermark");
    let rows=sqlx::query("SELECT DISTINCT ON(field) field,definition::text AS definition FROM mdm.field_versions WHERE tenant_id=$1::uuid AND revision<=$2 ORDER BY field,version DESC LIMIT 1025")
        .bind(tenant.to_string()).bind(watermark).fetch_all(c).await?;
    ensure!(rows.len() <= 1024, "field catalog capacity");
    let mut fields: BTreeMap<_, _> = builtin::fields().into_iter().map(|f| (f.key, f)).collect();
    for row in rows {
        let key = FieldKey::parse(row.try_get("field")?)?;
        if let Some(body) = row.try_get::<Option<String>, _>("definition")? {
            let field: FieldDefinition = serde_json::from_str(&body)?;
            ensure!(field.key == key, "field identity mismatch");
            field.validate()?;
            fields.insert(key, field);
        } else {
            fields.remove(&key);
        }
    }
    Ok(Catalog::new(fields.into_values().collect())?)
}
/// Read current field definitions using the caller's database snapshot.
pub async fn catalog_in(c: &mut PgConnection, tenant: TenantId) -> Result<Catalog> {
    catalog_at_in(c, tenant, i64::MAX).await
}

/// Publish an authorized field CAS and its invalidation fact in the same transaction.
/// The service checks references before invoking this storage boundary.
pub async fn publish_field_in(
    c: &mut PgConnection,
    tenant: TenantId,
    expected: u64,
    field: &FieldDefinition,
) -> Result<bool> {
    crate::reader::assert_tenant(c, tenant).await?;
    field.validate()?;
    ensure!(
        expected < i64::MAX as u64 && field.version == expected + 1,
        "invalid field revision"
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2554))")
        .bind(format!("{tenant}:field-catalog"))
        .execute(&mut *c)
        .await?;
    let catalog = catalog_in(c, tenant).await?;
    let old = catalog.definition(field.key).ok();
    let latest: Option<i64> = sqlx::query_scalar(
        "SELECT max(version) FROM mdm.field_versions WHERE tenant_id=$1::uuid AND field=$2",
    )
    .bind(tenant.to_string())
    .bind(field.key.as_str())
    .fetch_one(&mut *c)
    .await?;
    let actual = latest
        .map(|v| v as u64)
        .or_else(|| old.map(|f| f.version))
        .unwrap_or(0);
    ensure!(
        old.is_some() || latest.is_none(),
        "retired field identity cannot be reused"
    );
    if actual != expected {
        return Ok(false);
    }
    if let Some(seed) = builtin::fields().into_iter().find(|f| f.key == field.key) {
        ensure!(
            seed.value_type == field.value_type
                && seed.nullable == field.nullable
                && seed.manual == field.manual
                && seed.item_key == field.item_key
                && field.sources.keys().all(|s| seed.sources.contains_key(s)),
            "system field contract is immutable"
        );
    } else {
        ensure!(
            field.key.as_str().starts_with("custom."),
            "reserved field namespace"
        );
    }
    if let Some(old) = old {
        ensure!(
            old.value_type == field.value_type
                && old.item_key == field.item_key
                && old.unit == field.unit,
            "field type replacement requires a new key"
        );
    }
    ensure!(
        old.is_some() || catalog.fields().count() < 1024,
        "field catalog capacity"
    );
    let mut candidates: Vec<_> = catalog
        .fields()
        .filter(|f| f.key != field.key)
        .cloned()
        .collect();
    candidates.push(field.clone());
    Catalog::new(candidates)?;
    let body = serde_json::to_string(field)?;
    ensure!(body.len() <= 65536, "field definition capacity");
    let revision:i64=sqlx::query_scalar("SELECT mdm.record_asset_change($1::uuid,'catalog',jsonb_build_object('field',$2::text),ARRAY[$2::text])")
        .bind(tenant.to_string()).bind(field.key.as_str()).fetch_one(&mut *c).await?;
    sqlx::query("INSERT INTO mdm.field_versions VALUES($1::uuid,$2,$3,$4,$5::jsonb)")
        .bind(tenant.to_string())
        .bind(field.key.as_str())
        .bind(field.version as i64)
        .bind(revision)
        .bind(body)
        .execute(c)
        .await?;
    Ok(true)
}
/// Retire an unreferenced custom field; retain all published definitions and CAS history.
pub async fn retire_field_in(
    c: &mut PgConnection,
    tenant: TenantId,
    key: FieldKey,
    expected: u64,
) -> Result<bool> {
    crate::reader::assert_tenant(c, tenant).await?;
    ensure!(
        expected > 0
            && expected < i64::MAX as u64
            && !builtin::fields().iter().any(|f| f.key == key),
        "system field cannot be removed"
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2554))")
        .bind(format!("{tenant}:field-catalog"))
        .execute(&mut *c)
        .await?;
    let catalog = catalog_in(c, tenant).await?;
    if catalog.definition(key).ok().map(|f| f.version) != Some(expected) {
        return Ok(false);
    }
    let revision:i64=sqlx::query_scalar("SELECT mdm.record_asset_change($1::uuid,'catalog',jsonb_build_object('field',$2::text),ARRAY[$2::text])")
        .bind(tenant.to_string()).bind(key.as_str()).fetch_one(&mut *c).await?;
    sqlx::query("INSERT INTO mdm.field_versions VALUES($1::uuid,$2,$3,$4,NULL)")
        .bind(tenant.to_string())
        .bind(key.as_str())
        .bind((expected + 1) as i64)
        .bind(revision)
        .execute(c)
        .await?;
    Ok(true)
}
/// Register a frozen collector definition before accepting its first report.
/// Replay compares the entire definition; the same version cannot change its content.
pub async fn register_collection_in(
    c: &mut PgConnection,
    tenant: TenantId,
    definition: &CollectionDefinition,
) -> Result<()> {
    crate::reader::assert_tenant(c, tenant).await?;
    let fingerprint = definition.fingerprint()?;
    let coverage = serde_json::to_string(&definition.coverage()?)?;
    let body = serde_json::to_string(definition)?;
    ensure!(body.len() <= 1048576, "collection contract capacity");
    let existing:Option<String>=sqlx::query_scalar("SELECT fingerprint FROM mdm.collection_definitions WHERE tenant_id=$1::uuid AND dataset=$2 AND source=$3 AND version=$4")
        .bind(tenant.to_string()).bind(definition.dataset()).bind(definition.source().as_str()).bind(definition.version()).fetch_optional(&mut *c).await?;
    if let Some(old) = existing {
        ensure!(old == fingerprint, "collection definition conflict");
        return Ok(());
    }
    let catalog = catalog_in(c, tenant).await?;
    for field in definition.fields() {
        ensure!(
            catalog.definition(field.key)? == field,
            "collection field version is not current"
        )
    }
    sqlx::query("INSERT INTO mdm.collection_definitions VALUES($1::uuid,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT DO NOTHING")
        .bind(tenant.to_string()).bind(definition.dataset()).bind(definition.version()).bind(definition.source().as_str()).bind(&fingerprint).bind(&coverage).bind(body).execute(&mut *c).await?;
    let stored = collection_in(c, tenant, definition.source(), &coverage).await?;
    ensure!(
        stored.fingerprint()? == fingerprint,
        "collection definition conflict"
    );
    Ok(())
}
/// Read and verify the immutable collection contract for an authenticated report coverage.
pub async fn collection_in(
    c: &mut PgConnection,
    tenant: TenantId,
    source: Source,
    coverage: &str,
) -> Result<CollectionDefinition> {
    crate::reader::assert_tenant(c, tenant).await?;
    let row=sqlx::query("SELECT definition::text AS definition,fingerprint,dataset,version FROM mdm.collection_definitions WHERE tenant_id=$1::uuid AND source=$2 AND coverage=$3")
        .bind(tenant.to_string()).bind(source.as_str()).bind(coverage).fetch_one(c).await?;
    let definition: CollectionDefinition = serde_json::from_str(row.try_get("definition")?)?;
    ensure!(
        definition.source() == source
            && definition.dataset() == row.try_get::<&str, _>("dataset")?
            && definition.version() == row.try_get::<&str, _>("version")?
            && definition.fingerprint()? == row.try_get::<String, _>("fingerprint")?
            && serde_json::to_string(&definition.coverage()?)? == coverage,
        "collection contract mismatch"
    );
    Ok(definition)
}

/// Enumerate registered collector datasets without a second static source catalogue.
pub async fn datasets_in(
    c: &mut PgConnection,
    tenant: TenantId,
) -> Result<BTreeMap<Source, Vec<String>>> {
    crate::reader::assert_tenant(c, tenant).await?;
    let rows=sqlx::query("SELECT DISTINCT source,dataset FROM mdm.collection_definitions WHERE tenant_id=$1::uuid ORDER BY source,dataset LIMIT 4097")
        .bind(tenant.to_string()).fetch_all(c).await?;
    ensure!(rows.len() <= 4096, "collection dataset capacity");
    let mut result: BTreeMap<Source, Vec<String>> = BTreeMap::new();
    for row in rows {
        result
            .entry(Source::parse(row.try_get("source")?)?)
            .or_default()
            .push(row.try_get("dataset")?);
    }
    Ok(result)
}

/// Reuse the immutable field binding already frozen for a template version.
pub async fn collection_version_in(
    c: &mut PgConnection,
    tenant: TenantId,
    source: Source,
    dataset: &str,
    version: &str,
) -> Result<Option<CollectionDefinition>> {
    crate::reader::assert_tenant(c, tenant).await?;
    let coverage:Option<String>=sqlx::query_scalar("SELECT coverage FROM mdm.collection_definitions WHERE tenant_id=$1::uuid AND source=$2 AND dataset=$3 AND version=$4")
        .bind(tenant.to_string()).bind(source.as_str()).bind(dataset).bind(version).fetch_optional(&mut *c).await?;
    match coverage {
        Some(coverage) => Ok(Some(collection_in(c, tenant, source, &coverage).await?)),
        None => Ok(None),
    }
}
