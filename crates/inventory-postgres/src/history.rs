//! Frozen reads use immutable owner history, never a long-lived database snapshot.
use anyhow::{Result, ensure};
use rss_observation::Scope;
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};

/// Read the last committed asset watermark in the host's tenant transaction.
pub async fn watermark_in(c: &mut PgConnection, tenant: TenantId) -> Result<i64> {
    crate::reader::assert_tenant(c, tenant).await?;
    Ok(sqlx::query_scalar(
        "SELECT coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0)",
    )
    .bind(tenant.to_string())
    .fetch_one(c)
    .await?)
}

/// Read an authenticated, bounded set of source coordinates at a committed watermark.
/// The host resolves the source authority at the SAME watermark. This function
/// does not authorize a source, claim universe completeness, or commit the transaction.
pub async fn read_at_in(
    c: &mut PgConnection,
    tenant: TenantId,
    scopes: &[Scope],
    watermark: i64,
) -> Result<Vec<crate::InventoryField>> {
    ensure!(
        watermark >= 0 && scopes.len() <= 2000,
        "invalid history page"
    );
    ensure!(
        scopes.iter().all(|s| s.tenant() == tenant
            && rss_mdm_inventory::Source::parse(s.source().as_str())
                .is_ok_and(|s| s != rss_mdm_inventory::Source::Manual)),
        "history source mismatch"
    );
    crate::reader::assert_tenant(c, tenant).await?;
    let scopes = scopes
        .iter()
        .map(Scope::encode)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let projection = crate::projection_scope(tenant);
    let rows = sqlx::query(
        r#"
      WITH requested AS (
        SELECT sha256(convert_to(jsonb_build_array($2::text,$3::text,s)::text,'UTF8')) AS digest
        FROM unnest($4::text[]) s
      ), latest AS (
        SELECT DISTINCT ON(h.scope_digest,h.field) h.scope_digest,h.field,h.document
        FROM mdm.inventory_history h JOIN requested q ON q.digest=h.scope_digest
        WHERE h.tenant_id=$1::uuid AND h.revision<=$5
        ORDER BY h.scope_digest,h.field,h.revision DESC
      )
      SELECT DISTINCT ON(r.scope,r.field) r.*,d.definition::text AS definition FROM latest h
      CROSS JOIN LATERAL jsonb_populate_record(NULL::mdm.inventory,h.document) r
      JOIN mdm.collection_definitions d ON(d.tenant_id,d.coverage,d.source)=(r.tenant_id,r.coverage,r.source)
      WHERE h.document IS NOT NULL AND r.journal=$2 AND r.generation=$3 AND r.scope=ANY($4)
      ORDER BY r.scope,r.field,r.collection_sequence DESC
    "#,
    )
    .bind(tenant.to_string())
    .bind(projection.source().source())
    .bind(projection.generation())
    .bind(scopes)
    .bind(watermark)
    .fetch_all(c)
    .await?;
    crate::reader::decode_rows(rows)
}

/// Read Manual values and tombstones at the same watermark as collected facts.
pub async fn manual_at_in(
    c: &mut PgConnection,
    tenant: TenantId,
    devices: &[String],
    watermark: i64,
) -> Result<Vec<crate::Assignment>> {
    ensure!(
        watermark >= 0 && devices.len() <= 1000,
        "invalid manual history page"
    );
    crate::reader::assert_tenant(c, tenant).await?;
    let rows = sqlx::query(
        r#"
      WITH latest AS (
        SELECT DISTINCT ON(device,field) document FROM mdm.manual_history
        WHERE tenant_id=$1::uuid AND device=ANY($2) AND revision<=$3
        ORDER BY device,field,revision DESC
      ) SELECT r.device,r.field,r.revision,r.fact::text FROM latest h
        CROSS JOIN LATERAL jsonb_populate_record(NULL::mdm.manual_assignments,h.document) r
        WHERE h.document IS NOT NULL ORDER BY r.device,r.field
    "#,
    )
    .bind(tenant.to_string())
    .bind(devices)
    .bind(watermark)
    .fetch_all(c)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(crate::Assignment {
                device: r.try_get("device")?,
                field: rss_mdm_inventory::FieldKey::parse(r.try_get("field")?)?,
                revision: r.try_get("revision")?,
                fact: serde_json::from_str(r.try_get("fact")?)?,
            })
        })
        .collect()
}
