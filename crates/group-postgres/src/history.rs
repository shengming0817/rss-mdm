//! Sparse calculation history. A full result resets the baseline; deltas share prior rows.
use crate::{storage::stored_shape, *};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::Row;

pub(crate) async fn metadata(
    tx: &mut PgTransaction<'_>,
    id: OperationId,
    after: Option<String>,
    selected: Option<Vec<String>>,
    limit: usize,
    matched_only: bool,
) -> Result<Vec<sqlx::postgres::PgRow>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("WITH wanted AS (SELECT group_id,base_calculation,floor_revision FROM mdm_group.member_runs WHERE tenant_id=$1::uuid AND id=$2::uuid), latest AS (SELECT DISTINCT ON (r.object_id) r.object_id,r.run_id::text AS run_id,r.matched,octet_length(r.evidence) AS bytes FROM mdm_group.member_rows r JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(r.tenant_id,r.run_id) JOIN wanted w ON b.group_id=w.group_id WHERE r.tenant_id=$1::uuid AND (b.id=$2::uuid OR (b.phase='published' AND b.base_calculation>=w.floor_revision AND b.base_calculation<w.base_calculation)) AND r.object_id>coalesce($3,'') COLLATE \"C\" AND ($4::text[] IS NULL OR r.object_id=ANY($4)) ORDER BY r.object_id,b.base_calculation DESC) SELECT * FROM latest WHERE NOT $6 OR matched ORDER BY object_id LIMIT $5")
            .bind(tenant).bind(id.to_string()).bind(after).bind(selected).bind(limit as i64).bind(matched_only).fetch_all(c).await
    })).await
}
pub(crate) async fn rows(
    tx: &mut PgTransaction<'_>,
    id: OperationId,
    after: Option<String>,
    limit: usize,
) -> Result<Vec<sqlx::postgres::PgRow>, PgError> {
    let metadata = metadata(tx, id, after, None, limit, false).await?;
    let mut devices = Vec::new();
    let mut runs = Vec::new();
    let mut bytes = 0usize;
    for row in metadata {
        let size = row.try_get::<i32, _>("bytes")? as usize + 1024;
        if bytes + size > 16 * 1024 * 1024 {
            break;
        }
        bytes += size;
        devices.push(row.try_get::<String, _>("object_id")?);
        runs.push(row.try_get::<String, _>("run_id")?);
    }
    let tenant = tx.tenant_id().to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("SELECT r.object_id,r.matched,r.evidence,r.evidence_digest FROM unnest($2::text[],$3::text[]) AS selected(device,run) JOIN mdm_group.member_rows r ON r.object_id=selected.device AND r.run_id=selected.run::uuid WHERE r.tenant_id=$1::uuid ORDER BY r.object_id")
            .bind(tenant).bind(devices).bind(runs).fetch_all(c).await
    })).await?;
    if rows.len() > limit {
        return Err(stored_shape());
    }
    Ok(rows)
}
