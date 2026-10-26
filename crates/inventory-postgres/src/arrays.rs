//! Immutable canonical arrays with ordinal and cumulative-byte indexes.
//! ref: PostgreSQL REL_17_STABLE executor; admit bounded metadata before fetching payload.
use anyhow::{Result, ensure};
use rss_mdm_inventory::{FieldDefinition, FieldKey, Scalar};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::collections::BTreeMap;
mod scan;
pub use scan::{ArrayScanState, ScanChunk, advance_scan, start_scan};
const PREFIX: &[u8] = b"{\"kind\":\"array\",\"value\":[";
const SUFFIX: &[u8] = b"]}";

/// Immutable version metadata. Resolve resource/source authority before reading this value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    /// Content and immutable field-definition binding.
    pub version: String,
    /// Owning field.
    pub field: FieldKey,
    /// SHA-256 of the immutable definition used to validate these items.
    pub definition_digest: String,
    /// Number of ordinal items, including zero for an empty known array.
    pub count: usize,
    /// Exact canonical Scalar bytes, including array punctuation.
    pub bytes: usize,
    /// SHA-256 of the full canonical Scalar representation.
    pub digest: String,
}
/// Producer-owned preparation; insertion borrows the original transaction.
pub(crate) struct Prepared {
    pub metadata: Metadata,
    definition: Vec<u8>,
    items: Vec<Vec<u8>>,
    ends: Vec<i64>,
}
pub(crate) fn prepare(definition: &FieldDefinition, values: &[Scalar]) -> Result<Prepared> {
    let Scalar::Array(values) = definition.canonical_value(Scalar::Array(values.to_vec()))? else {
        anyhow::bail!("array definition");
    };
    let field = definition.key;
    let definition = serde_json::to_vec(definition)?;
    let definition_digest = format!("{:x}", Sha256::digest(&definition));
    let mut hash = Sha256::new();
    hash.update(PREFIX);
    let mut items = Vec::with_capacity(values.len());
    let mut ends = Vec::with_capacity(values.len());
    let mut bytes = 0usize;
    for value in &values {
        let item = serde_json::to_vec(value)?;
        if !items.is_empty() {
            hash.update(b",");
            bytes += 1;
        }
        bytes = bytes
            .checked_add(item.len())
            .ok_or_else(|| anyhow::anyhow!("array byte overflow"))?;
        hash.update(&item);
        ends.push(i64::try_from(bytes)?);
        items.push(item);
    }
    hash.update(SUFFIX);
    let digest = format!("{:x}", hash.finalize());
    let version = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(1, &definition_digest, &digest))?)
    );
    // Field is bound independently of the digest by the immutable definition hash.
    Ok(Prepared {
        metadata: Metadata {
            version,
            field,
            definition_digest,
            count: items.len(),
            bytes: bytes + PREFIX.len() + SUFFIX.len(),
            digest,
        },
        definition,
        items,
        ends,
    })
}

pub(crate) async fn store(c: &mut PgConnection, tenant: TenantId, value: &Prepared) -> Result<()> {
    crate::reader::assert_tenant(c, tenant).await?;
    let m = &value.metadata;
    let changed=sqlx::query("INSERT INTO mdm.array_versions(tenant_id,version,format,field,definition_digest,item_count,canonical_bytes,digest,definition) VALUES($1::uuid,$2,1,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING")
        .bind(tenant.to_string()).bind(&m.version).bind(m.field.as_str()).bind(&m.definition_digest).bind(m.count as i64).bind(m.bytes as i64).bind(&m.digest).bind(&value.definition).execute(&mut *c).await?.rows_affected();
    if changed == 0 {
        let old = metadata(c, tenant, std::slice::from_ref(&m.version)).await?;
        ensure!(
            old.get(&m.version) == Some(m),
            "array immutable identity mismatch"
        );
        return Ok(());
    }
    for (batch, items) in value.items.chunks(128).enumerate() {
        let start = batch * 128;
        let ordinals = (start..start + items.len())
            .map(|n| n as i64)
            .collect::<Vec<_>>();
        let ends = value.ends[start..start + items.len()].to_vec();
        sqlx::query("INSERT INTO mdm.array_items(tenant_id,version,ordinal,payload,digest,prefix_bytes) SELECT $1::uuid,$2,q.ordinal,q.payload,sha256(q.payload),q.bytes FROM unnest($3::bigint[],$4::bytea[],$5::bigint[]) q(ordinal,payload,bytes)")
            .bind(tenant.to_string()).bind(&m.version).bind(ordinals).bind(items).bind(ends).execute(&mut *c).await?;
    }
    Ok(())
}
/// Fetch only small version metadata for a bounded authorized set.
pub async fn metadata(
    c: &mut PgConnection,
    tenant: TenantId,
    versions: &[String],
) -> Result<BTreeMap<String, Metadata>> {
    if versions.is_empty() {
        return Ok(BTreeMap::new());
    }
    crate::reader::assert_tenant(c, tenant).await?;
    let rows=sqlx::query("SELECT version,format,field,definition_digest,item_count,canonical_bytes,digest FROM mdm.array_versions WHERE tenant_id=$1::uuid AND version=ANY($2)")
        .bind(tenant.to_string()).bind(versions).fetch_all(c).await?;
    let mut result = BTreeMap::new();
    for row in rows {
        ensure!(row.try_get::<i32, _>("format")? == 1, "array format");
        let m = Metadata {
            version: row.try_get("version")?,
            field: FieldKey::parse(row.try_get("field")?)?,
            definition_digest: row.try_get("definition_digest")?,
            count: usize::try_from(row.try_get::<i64, _>("item_count")?)?,
            bytes: usize::try_from(row.try_get::<i64, _>("canonical_bytes")?)?,
            digest: row.try_get("digest")?,
        };
        result.insert(m.version.clone(), m);
    }
    ensure!(
        versions.iter().all(|v| result.contains_key(v)),
        "missing array version"
    );
    Ok(result)
}
/// A page admitted by item count and canonical payload bytes before decoding.
pub struct Page {
    /// Complete immutable version metadata.
    pub metadata: Metadata,
    /// Only admitted items.
    pub items: Vec<Scalar>,
    /// Next ordinal, absent after the final item.
    pub next: Option<usize>,
}
/// Read one authorized immutable array, without taking a whole-array allocation.
pub async fn page(
    c: &mut PgConnection,
    tenant: TenantId,
    version: &str,
    after: usize,
    limit: usize,
    byte_limit: usize,
) -> Result<Page> {
    ensure!(
        (1..=1000).contains(&limit) && (1..=16 * 1024 * 1024).contains(&byte_limit),
        "array page budget"
    );
    let m = metadata(c, tenant, &[version.to_owned()])
        .await?
        .remove(version)
        .ok_or_else(|| anyhow::anyhow!("array metadata"))?;
    ensure!(after <= m.count, "array cursor ordinal");
    let definition:Vec<u8>=sqlx::query_scalar("SELECT definition FROM mdm.array_versions WHERE tenant_id=$1::uuid AND version=$2 AND octet_length(definition)<=65536")
        .bind(tenant.to_string()).bind(version).fetch_one(&mut *c).await?;
    ensure!(
        format!("{:x}", Sha256::digest(&definition)) == m.definition_digest,
        "array definition digest"
    );
    let definition: FieldDefinition = serde_json::from_slice(&definition)?;
    ensure!(definition.key == m.field, "array definition field");
    let rows:Vec<(i64,i64,i32)>=sqlx::query_as("SELECT ordinal,prefix_bytes,item_bytes FROM mdm.array_items WHERE tenant_id=$1::uuid AND version=$2 AND ordinal>=$3 ORDER BY ordinal LIMIT $4")
        .bind(tenant.to_string()).bind(version).bind(after as i64).bind(limit as i64).fetch_all(&mut *c).await?;
    ensure!(
        after + rows.len() <= m.count,
        "array metadata/item count mismatch"
    );
    let mut selected = Vec::new();
    let mut used = 0usize;
    let mut previous = None;
    for (ordinal, end, size) in rows {
        ensure!(
            ordinal as usize == after + selected.len() && size > 0,
            "array ordinal integrity"
        );
        if let Some(previous) = previous {
            ensure!(
                end - previous == i64::from(size) + 1,
                "array byte index integrity"
            );
        }
        if used
            .checked_add(size as usize)
            .is_none_or(|total| total > byte_limit)
        {
            break;
        }
        used += size as usize;
        selected.push(ordinal);
        previous = Some(end);
    }
    ensure!(
        after == m.count || !selected.is_empty(),
        "array item exceeds page budget or is missing"
    );
    let items=sqlx::query_as::<_,(Vec<u8>,Vec<u8>)>("SELECT payload,digest FROM mdm.array_items WHERE tenant_id=$1::uuid AND version=$2 AND ordinal=ANY($3) ORDER BY ordinal")
        .bind(tenant.to_string()).bind(version).bind(&selected).fetch_all(c).await?;
    ensure!(items.len() == selected.len(), "array page missing item");
    let items = items
        .into_iter()
        .map(|(bytes, digest)| {
            ensure!(
                Sha256::digest(&bytes).as_slice() == digest,
                "array item digest"
            );
            Ok(serde_json::from_slice(&bytes)?)
        })
        .collect::<Result<Vec<_>>>()?;
    for item in &items {
        definition.validate_item(item)?;
    }
    let end = after + selected.len();
    Ok(Page {
        metadata: m.clone(),
        items,
        next: (end < m.count).then_some(end),
    })
}

pub(crate) fn storage_error(error: anyhow::Error) -> sqlx::Error {
    match error.downcast::<sqlx::Error>() {
        Ok(error) => error,
        Err(_) => sqlx::Error::Protocol("array storage invariant".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn definition() -> FieldDefinition {
        let mut definition = rss_mdm_inventory::builtin::fields()
            .into_iter()
            .find(|d| d.key == rss_mdm_inventory::builtin::OFFICE_FLOOR)
            .unwrap();
        definition.value_type = rss_mdm_inventory::ValueType::Array {
            items: Box::new(rss_mdm_inventory::ValueType::String {
                max_length: 256,
                allow_empty: true,
            }),
            max_items: 32,
        };
        definition
    }
    #[test]
    fn ordinal_index_and_digest_preserve_exact_empty_and_unicode_canonical_arrays() {
        let definition = definition();
        for values in [
            vec![],
            vec![
                Scalar::String("中文🙂\n\"".into()),
                Scalar::String(String::new()),
                Scalar::String("a\\b".into()),
            ],
        ] {
            let prepared = prepare(&definition, &values).unwrap();
            let canonical = serde_json::to_vec(&Scalar::Array(values.clone())).unwrap();
            assert_eq!(prepared.metadata.field, definition.key);
            assert_eq!(prepared.metadata.bytes, canonical.len());
            assert_eq!(
                prepared.metadata.digest,
                format!("{:x}", Sha256::digest(&canonical))
            );
            assert_eq!(prepared.metadata.count, values.len());
            let mut bytes = 0;
            for (ordinal, item) in prepared.items.iter().enumerate() {
                bytes += item.len() + usize::from(ordinal > 0);
                assert_eq!(prepared.ends[ordinal], bytes as i64);
                assert_eq!(
                    serde_json::from_slice::<Scalar>(item).unwrap(),
                    values[ordinal]
                );
            }
            assert_eq!(
                prepare(&definition, &values).unwrap().metadata,
                prepared.metadata
            );
        }
    }
    #[test]
    fn versions_bind_field_definition_and_reject_wrong_element_types() {
        let mut definition = definition();
        let values = vec![Scalar::String("same".into())];
        let first = prepare(&definition, &values).unwrap();
        definition.version += 1;
        let second = prepare(&definition, &values).unwrap();
        assert_ne!(first.metadata.version, second.metadata.version);
        assert_eq!(first.metadata.digest, second.metadata.digest);
        assert!(prepare(&definition, &[Scalar::Integer(1)]).is_err());
    }
}

/// One authorized observed array's metadata and exact source coordinates.
#[derive(Clone, Debug, Serialize)]
pub struct InventoryArray {
    /// Complete encoded observation scope.
    pub scope: String,
    /// Catalog field key.
    pub field: FieldKey,
    /// Source state without item payloads.
    pub fact: rss_mdm_inventory::ArrayFact,
}
fn value(meta: &Metadata, field: FieldKey) -> Result<rss_mdm_inventory::ArrayValue> {
    ensure!(meta.field == field, "array field binding");
    Ok(rss_mdm_inventory::ArrayValue {
        version: meta.version.clone(),
        count: meta.count,
        bytes: meta.bytes,
        digest: meta.digest.clone(),
    })
}
/// Fixed-watermark metadata read; no array payload is fetched or decoded.
pub async fn read_at_in(
    c: &mut PgConnection,
    tenant: TenantId,
    scopes: &[rss_observation::Scope],
    watermark: i64,
    fields: &[FieldKey],
) -> Result<Vec<InventoryArray>> {
    let rows = crate::history::rows_at_in(c, tenant, scopes, watermark, fields).await?;
    decode_observed(c, tenant, rows).await
}

pub(crate) async fn decode_observed(
    c: &mut PgConnection,
    tenant: TenantId,
    rows: Vec<sqlx::postgres::PgRow>,
) -> Result<Vec<InventoryArray>> {
    let mut versions = std::collections::BTreeSet::new();
    for row in &rows {
        for column in ["value_version", "last_known_version"] {
            if let Some(id) = row.try_get::<Option<String>, _>(column)? {
                versions.insert(id);
            }
        }
    }
    let versions = metadata(c, tenant, &versions.into_iter().collect::<Vec<_>>()).await?;
    rows.into_iter()
        .map(|row| {
            use rss_mdm_inventory::{
                ArrayFact, ArrayKnownValue, ArrayState as S, UnknownReason as U,
            };
            let envelope = crate::reader::envelope(&row)?;
            ensure!(
                matches!(
                    envelope.definition.value_type,
                    rss_mdm_inventory::ValueType::Array { .. }
                ),
                "non-array metadata request"
            );
            let get = |column: &str| -> Result<Option<rss_mdm_inventory::ArrayValue>> {
                row.try_get::<Option<String>, _>(column)?
                    .map(|id| {
                        value(
                            versions
                                .get(&id)
                                .ok_or_else(|| anyhow::anyhow!("missing array version"))?,
                            envelope.field,
                        )
                    })
                    .transpose()
            };
            let state = match row.try_get::<&str, _>("state")? {
                "known" => S::Known(
                    get("value_version")?
                        .ok_or_else(|| anyhow::anyhow!("missing current array"))?,
                ),
                "null" => S::Null,
                "deleted" => S::Deleted,
                "unsupported" => S::Unsupported,
                "unknown_conflict" => S::Unknown {
                    reason: U::UnorderedConflict,
                },
                "unknown_incomplete" => S::Unknown {
                    reason: U::Incomplete,
                },
                "unknown_native" => S::Unknown {
                    reason: U::NativeStatus,
                },
                "unknown_limit" => S::Unknown {
                    reason: U::EvidenceLimit,
                },
                _ => anyhow::bail!("invalid array source state"),
            };
            let last_known = get("last_known_version")?
                .map(|value| {
                    let mut evidence = envelope.evidence.clone();
                    evidence.snapshot_id = row.try_get("last_known_batch")?;
                    evidence.observed_at = row.try_get("last_known_observed")?;
                    evidence.received_at = row.try_get("last_known_received")?;
                    Ok::<_, anyhow::Error>(ArrayKnownValue { value, evidence })
                })
                .transpose()?;
            Ok(InventoryArray {
                scope: envelope.scope,
                field: envelope.field,
                fact: ArrayFact {
                    state,
                    last_known,
                    evidence: envelope.evidence,
                },
            })
        })
        .collect()
}
/// Manual array metadata at a frozen watermark.
#[derive(Clone, Debug, Serialize)]
pub struct ManualArray {
    /// Authorized owning endpoint.
    pub device: String,
    /// Field key.
    pub field: FieldKey,
    /// Manual CAS revision.
    pub revision: i64,
    /// Source state without array item payloads.
    pub fact: rss_mdm_inventory::ArrayFact,
}
/// Read selected manual array fields without materializing current or last-known arrays.
pub async fn manual_at_in(
    c: &mut PgConnection,
    tenant: TenantId,
    devices: &[String],
    watermark: i64,
    fields: &[FieldKey],
) -> Result<Vec<ManualArray>> {
    ensure!(
        devices.len() <= 10_000 && watermark >= 0,
        "manual array request bound"
    );
    crate::reader::assert_tenant(c, tenant).await?;
    let rows=sqlx::query("WITH latest AS (SELECT DISTINCT ON(device,field) document FROM mdm.manual_history WHERE tenant_id=$1::uuid AND device=ANY($2) AND revision<=$3 AND field=ANY($4) ORDER BY device,field,revision DESC) SELECT r.device,r.field,r.revision,r.fact,r.value_version,r.last_known_version FROM latest h CROSS JOIN LATERAL jsonb_populate_record(NULL::mdm.manual_assignments,h.document) r WHERE h.document IS NOT NULL ORDER BY r.device,r.field")
        .bind(tenant.to_string()).bind(devices).bind(watermark).bind(fields.iter().map(|f|f.as_str()).collect::<Vec<_>>()).fetch_all(&mut *c).await?;
    decode_manual(c, tenant, rows).await
}

pub(crate) async fn decode_manual(
    c: &mut PgConnection,
    tenant: TenantId,
    rows: Vec<sqlx::postgres::PgRow>,
) -> Result<Vec<ManualArray>> {
    let mut versions = std::collections::BTreeSet::new();
    for row in &rows {
        for column in ["value_version", "last_known_version"] {
            if let Some(id) = row.try_get::<Option<String>, _>(column)? {
                versions.insert(id);
            }
        }
    }
    let versions = metadata(c, tenant, &versions.into_iter().collect::<Vec<_>>()).await?;
    rows.into_iter()
        .map(|row| {
            let field = FieldKey::parse(row.try_get("field")?)?;
            let mut document: serde_json::Value = row.try_get("fact")?;
            for (column, target) in [
                ("value_version", "state"),
                ("last_known_version", "lastKnown"),
            ] {
                if let Some(id) = row.try_get::<Option<String>, _>(column)? {
                    ensure!(
                        document[target].is_object() && document[target].get("value").is_none(),
                        "manual metadata shape"
                    );
                    document[target]["value"] = serde_json::to_value(value(
                        versions
                            .get(&id)
                            .ok_or_else(|| anyhow::anyhow!("missing array version"))?,
                        field,
                    )?)?;
                }
            }
            Ok(ManualArray {
                device: row.try_get("device")?,
                field,
                revision: row.try_get("revision")?,
                fact: serde_json::from_value(document)?,
            })
        })
        .collect()
}
