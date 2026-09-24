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
        scopes
            .iter()
            .all(|s| s.tenant() == tenant && rss_mdm_inventory::scope_coverage(s).is_ok()),
        "history source mismatch"
    );
    crate::reader::assert_tenant(c, tenant).await?;
    let coverage = scopes
        .iter()
        .map(|s| {
            Ok(serde_json::to_string(&rss_mdm_inventory::scope_coverage(
                s,
            )?)?)
        })
        .collect::<Result<Vec<_>>>()?;
    let scopes = scopes
        .iter()
        .map(Scope::encode)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let projection = crate::projection_scope(tenant);
    let rows = sqlx::query(
        r#"
      WITH requested AS (
        SELECT sha256(convert_to(jsonb_build_array($2::text,$3::text,s,c)::text,'UTF8')) AS digest
        FROM unnest($5::text[],$4::text[]) AS requested_scopes(s,c)
      ), latest AS (
        SELECT DISTINCT ON(h.scope_digest,h.field) h.scope_digest,h.field,h.document
        FROM mdm.inventory_history h JOIN requested r ON r.digest=h.scope_digest
        WHERE h.tenant_id=$1::uuid AND h.revision<=$6
        ORDER BY h.scope_digest,h.field,h.revision DESC
      )
      SELECT r.* FROM latest h
      CROSS JOIN LATERAL jsonb_populate_record(NULL::mdm.inventory,h.document) r
      WHERE h.document IS NOT NULL ORDER BY r.scope,r.field
    "#,
    )
    .bind(tenant.to_string())
    .bind(projection.source().source())
    .bind(projection.generation())
    .bind(coverage)
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
