//! Catalog and frozen collection contracts borrow the caller's tenant transaction.
use anyhow::{Result, ensure};
use rss_mdm_inventory::{
    Catalog, CollectionDefinition, FieldDefinition, FieldKey, Source, builtin,
};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use std::collections::BTreeMap;

/// Load the single published catalog at a committed input watermark.
/// Initialization is explicit; reads never reconstruct retired or absent seed definitions.
pub async fn catalog_at_in(
    c: &mut PgConnection,
    tenant: TenantId,
    watermark: i64,
) -> Result<Catalog> {
    crate::reader::assert_tenant(c, tenant).await?;
    ensure!(watermark >= 0, "invalid catalog watermark");
    let rows=sqlx::query("SELECT field,definition::text AS definition FROM (SELECT DISTINCT ON(field) field,definition FROM mdm.field_versions WHERE tenant_id=$1::uuid AND revision<=$2 ORDER BY field,version DESC) latest WHERE definition IS NOT NULL ORDER BY field LIMIT 1025")
        .bind(tenant.to_string()).bind(watermark).fetch_all(c).await?;
    ensure!(rows.len() <= 1024, "field catalog capacity");
    let fields = rows
        .into_iter()
        .map(|row| {
            let key = FieldKey::parse(row.try_get("field")?)?;
            let field: FieldDefinition = serde_json::from_str(row.try_get("definition")?)?;
            ensure!(field.key == key, "field identity mismatch");
            field.validate()?;
            Ok(field)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Catalog::new(fields)?)
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
    if old.is_none() && latest.is_some() {
        return Ok(false);
    }
    if actual != expected {
        return Ok(false);
    }
    if builtin::protected(field.key) {
        let seed = builtin::fields()
            .into_iter()
            .find(|f| f.key == field.key)
            .expect("protected field seed");
        ensure!(
            seed.value_type == field.value_type
                && seed.nullable == field.nullable
                && seed.manual == field.manual
                && seed.item_key == field.item_key
                && seed.unit == field.unit
                && seed.sensitivity == field.sensitivity
                && field.sources.keys().all(|s| seed.sources.contains_key(s)),
            "core field contract is immutable"
        );
    } else if old.is_none() {
        ensure!(
            field.key.as_str().starts_with("custom.")
                || builtin::fields().iter().any(|f| f == field),
            "reserved field namespace"
        );
    }
    if let Some(old) = old {
        ensure!(
            old.value_type == field.value_type
                && old.item_key == field.item_key
                && old.unit == field.unit
                && old.sensitivity == field.sensitivity,
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
    sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,$4::jsonb)")
        .bind(tenant.to_string())
        .bind(field.key.as_str())
        .bind(field.version as i64)
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
        expected > 0 && expected < i64::MAX as u64 && !builtin::protected(key),
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
    scope: &rss_mdm_inventory::CollectionScope,
) -> Result<BTreeMap<Source, Vec<String>>> {
    crate::reader::assert_tenant(c, tenant).await?;
    let rows=sqlx::query("SELECT DISTINCT source,dataset FROM mdm.collection_definitions WHERE tenant_id=$1::uuid AND EXISTS(SELECT 1 FROM jsonb_array_elements(definition->'fields') f WHERE f->'scope'=$2::jsonb) ORDER BY source,dataset LIMIT 4097")
        .bind(tenant.to_string()).bind(serde_json::to_string(scope)?).fetch_all(c).await?;
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

/// Initialize a tenant catalog in its creation transaction. Never resurrect a retired identity
/// or replace an existing tenant revision. Runtime reads do not call this function.
pub async fn initialize_fields_in(c: &mut PgConnection, tenant: TenantId) -> Result<()> {
    crate::reader::assert_tenant(c, tenant).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2554))")
        .bind(format!("{tenant}:field-catalog"))
        .execute(&mut *c)
        .await?;
    for field in builtin::fields() {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mdm.field_versions WHERE tenant_id=$1::uuid AND field=$2)",
        )
        .bind(tenant.to_string())
        .bind(field.key.as_str())
        .fetch_one(&mut *c)
        .await?;
        if !exists {
            ensure!(
                publish_field_in(c, tenant, 0, &field).await?,
                "field initialization conflict"
            );
        }
    }
    Ok(())
}

/// Installation SQL generated from the canonical builtin definitions; only the owner may seed.
pub fn tenant_seed_sql() -> &'static str {
    static SQL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SQL.get_or_init(|| {
        let statements = builtin::fields().into_iter().map(|field| {
            let body = serde_json::to_string(&field).expect("builtin field serialization").replace('\'', "''");
            format!("PERFORM mdm.append_field_version(t,'{}',{},'{}'::jsonb);", field.key.as_str(), field.version, body)
        }).collect::<Vec<_>>().join("\n");
        format!("CREATE FUNCTION mdm.seed_tenant_catalog(t uuid) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $seed$ BEGIN {statements} END; $seed$; REVOKE ALL ON FUNCTION mdm.seed_tenant_catalog(uuid) FROM PUBLIC;")
    })
}
