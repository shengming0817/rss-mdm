//! Sparse calculation history. A full result resets the baseline; deltas share prior rows.
use crate::storage::stored_shape;
use rss_mdm_agent_wire::ObjectRef;
use rss_mdm_group::OperationId;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::Row;

pub(crate) async fn metadata(
    tx: &mut PgTransaction<'_>,
    id: OperationId,
    after: Option<ObjectRef>,
    selected: Option<Vec<ObjectRef>>,
    limit: usize,
    matched_only: bool,
) -> Result<Vec<sqlx::postgres::PgRow>, PgError> {
    let tenant = tx.tenant_id().to_string();
    let selected_kinds = selected
        .as_ref()
        .map(|items| items.iter().map(|o| o.kind()).collect::<Vec<_>>());
    let selected_ids = selected
        .as_ref()
        .map(|items| items.iter().map(|o| o.uuid()).collect::<Vec<_>>());
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query(r#"WITH wanted AS (
          SELECT group_id,base_calculation,floor_revision FROM mdm_group.member_runs WHERE tenant_id=$1::uuid AND id=$2::uuid
        ), latest AS (
          SELECT DISTINCT ON(r.object_kind,r.object_id) r.object_kind,r.object_id,r.run_id,r.matched,octet_length(r.evidence) AS bytes
          FROM mdm_group.member_rows r JOIN mdm_group.member_runs b ON(b.tenant_id,b.id)=(r.tenant_id,r.run_id)
          JOIN wanted w ON b.group_id=w.group_id
          WHERE r.tenant_id=$1::uuid AND (b.id=$2::uuid OR (b.phase='published' AND b.base_calculation>=w.floor_revision AND b.base_calculation<w.base_calculation))
          AND ($3::smallint IS NULL OR (r.object_kind,r.object_id)>($3,$4::uuid))
          AND ($5::smallint[] IS NULL OR EXISTS(SELECT FROM unnest($5::smallint[],$6::uuid[]) s(kind,id) WHERE (s.kind,s.id)=(r.object_kind,r.object_id)))
          ORDER BY r.object_kind,r.object_id,b.base_calculation DESC
        ) SELECT * FROM latest WHERE NOT $8 OR matched ORDER BY object_kind,object_id LIMIT $7"#)
            .bind(tenant).bind(id.to_string()).bind(after.map(ObjectRef::kind)).bind(after.map(ObjectRef::uuid))
            .bind(selected_kinds).bind(selected_ids).bind(limit as i64).bind(matched_only).fetch_all(c).await
    })).await
}
pub(crate) async fn selected_rows(
    tx: &mut PgTransaction<'_>,
    id: OperationId,
    after: Option<ObjectRef>,
    selected: Option<Vec<ObjectRef>>,
    limit: usize,
    max_bytes: usize,
) -> Result<(Vec<sqlx::postgres::PgRow>, usize), PgError> {
    let metadata = metadata(tx, id, after, selected, limit, false).await?;
    let mut kinds = Vec::new();
    let mut ids = Vec::new();
    let mut runs = Vec::new();
    let mut bytes = 0usize;
    for row in metadata {
        let size = row.try_get::<i32, _>("bytes")? as usize + 1024;
        if bytes + size > max_bytes.min(16 * 1024 * 1024) {
            if ids.is_empty() {
                return Ok((Vec::new(), size));
            }
            break;
        }
        bytes += size;
        kinds.push(row.try_get::<i16, _>("object_kind")?);
        ids.push(row.try_get::<uuid::Uuid, _>("object_id")?);
        runs.push(row.try_get::<uuid::Uuid, _>("run_id")?);
    }
    let tenant = tx.tenant_id().to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("SELECT r.object_kind,r.object_id,r.matched,r.evidence,r.evidence_digest FROM unnest($2::smallint[],$3::uuid[],$4::uuid[]) s(kind,id,run) JOIN mdm_group.member_rows r ON(r.object_kind,r.object_id,r.run_id)=(s.kind,s.id,s.run) WHERE r.tenant_id=$1::uuid ORDER BY r.object_kind,r.object_id")
            .bind(tenant).bind(kinds).bind(ids).bind(runs).fetch_all(c).await
    })).await?;
    if rows.len() > limit {
        return Err(stored_shape());
    }
    Ok((rows, bytes))
}
