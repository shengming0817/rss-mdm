//! Authorized, immutable result reads. Cursor projection is part of its signature.
use super::*;
use rss_mdm_query::cursor::CursorCodec;
use serde::{Deserialize, Serialize};
use sqlx::Row;
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Position {
    Items { device: String },
    Facet { facet: Facet, label: String },
}
struct QueryState {
    summary: Summary,
    status: String,
    failure: Option<String>,
    ready: bool,
}
impl AssetService {
    async fn query_state_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        scope: &ReadScope,
    ) -> Result<QueryState> {
        let state = self.query_task_in(tx, task).await?;
        let owner = state.input.scope;
        let completed = state.completed;
        let failure = state.failure;
        let forwarded = state.started;
        if owner.subject != scope.subject
            || owner.collection_scope != scope.collection_scope
            || owner.devices != scope.devices
        {
            return Err(Error::Forbidden.into());
        }
        let status = if failure.is_some() {
            "failed"
        } else if completed {
            "completed"
        } else if forwarded {
            "running"
        } else {
            "pending"
        };
        Ok(QueryState {
            summary: state.summary,
            status: status.into(),
            ready: completed && failure.is_none(),
            failure,
        })
    }
    pub(super) async fn asset_query_status(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        scope: &ReadScope,
    ) -> Result<Response> {
        let state = self.query_state_in(tx, task, scope).await?;
        Ok(Response::QueryStatus {
            task,
            status: state.status,
            summary: state.summary,
            failure: state.failure,
            result_url: state
                .ready
                .then(|| format!("/api/v1/device-queries/{task}/items")),
        })
    }
    fn query_cursor(&self, token: &str, task: Uuid, scope: &ReadScope) -> Result<Position> {
        let codec = CursorCodec::from_key(self.asset_cursor_key.clone());
        let binding = digest(&("asset-results", self.tenant.to_string(), task, scope))?;
        codec
            .decode(
                &checked_input(rss_contract::PageCursor::parse(token))?,
                &binding,
            )
            .map_err(|_| Error::Conflict.into())
    }
    fn next_query_cursor(
        &self,
        task: Uuid,
        scope: &ReadScope,
        position: Position,
    ) -> Result<String> {
        let codec = CursorCodec::from_key(self.asset_cursor_key.clone());
        let binding = digest(&("asset-results", self.tenant.to_string(), task, scope))?;
        Ok(checked_input(codec.encode(&binding, &position))?
            .as_str()
            .to_owned())
    }
    pub(super) async fn asset_query_items(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        scope: &ReadScope,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Response> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::Malformed.into());
        }
        let state = self.query_state_in(tx, task, scope).await?;
        if !state.ready {
            return Err(Error::Conflict.into());
        }
        // Completed results are immutable. Recover the key by their indexed identity
        // within this signed task, rather than serializing a 1024-byte key as JSON
        // numbers (which can exceed PageCursor even for a valid stored result).
        let after_device = if let Some(token) = cursor {
            match self.query_cursor(token, task, scope)? {
                Position::Items { device } => Some(device),
                _ => return Err(Error::Conflict.into()),
            }
        } else {
            None
        };
        let tenant = self.tenant.to_string();
        let metadata=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT device,octet_length(document) AS bytes FROM mdm_assets.asset_query_results WHERE tenant_id=$1::uuid AND run=$2::uuid AND ($3::text IS NULL OR (sort_key,device)>(SELECT sort_key,device FROM mdm_assets.asset_query_results WHERE tenant_id=$1::uuid AND run=$2::uuid AND device=$3 COLLATE \"C\")) ORDER BY sort_key,device LIMIT $4")
                .bind(tenant).bind(task.to_string()).bind(after_device).bind((limit + 1) as i64).fetch_all(c).await
        })).await?;
        let mut more = metadata.len() > limit;
        let mut ids = Vec::new();
        let mut bytes = 0usize;
        let mut next = None;
        for row in metadata.into_iter().take(limit) {
            let size = row.try_get::<i32, _>("bytes")? as usize + 1024;
            if bytes + size > 16 * 1024 * 1024 {
                if ids.is_empty() {
                    return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
                }
                more = true;
                break;
            }
            let device: String = row.try_get("device")?;
            next = Some(Position::Items {
                device: device.clone(),
            });
            ids.push(device);
            bytes += size;
        }
        if !more {
            next = None;
        }
        let tenant = self.tenant.to_string();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT r.device,r.document,r.digest FROM unnest($3::text[]) WITH ORDINALITY p(device,n) JOIN mdm_assets.asset_query_results r ON r.device=p.device WHERE r.tenant_id=$1::uuid AND r.run=$2::uuid ORDER BY p.n")
                .bind(tenant).bind(task.to_string()).bind(ids).fetch_all(c).await
        })).await?;
        rss_mdm_query_postgres::observe_rows("assets.results", &rows)?;
        let mut items = Vec::new();
        for row in rows {
            let raw: Vec<u8> = row.try_get("document")?;
            if Sha256::digest(&raw).as_slice() != row.try_get::<Vec<u8>, _>("digest")? {
                return Err(Error::Unavailable(Failure::AssetsStorage).into());
            }
            let item: DeviceView = stored(serde_json::from_slice(&raw))?;
            if item.device != row.try_get::<String, _>("device")? {
                return Err(Error::Unavailable(Failure::AssetsStorage).into());
            }
            items.push(item);
        }
        Ok(Response::Page {
            items,
            next_cursor: next
                .map(|position| self.next_query_cursor(task, scope, position))
                .transpose()?,
            snapshot: task.to_string(),
            summary: state.summary,
        })
    }
    pub(super) async fn asset_query_facets(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        scope: &ReadScope,
        facet: Facet,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Response> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::Malformed.into());
        }
        if !self.query_state_in(tx, task, scope).await?.ready {
            return Err(Error::Conflict.into());
        }
        let after = if let Some(token) = cursor {
            match self.query_cursor(token, task, scope)? {
                Position::Facet {
                    facet: bound,
                    label,
                } if bound == facet => Some(label),
                _ => return Err(Error::Conflict.into()),
            }
        } else {
            None
        };
        let tenant = self.tenant.to_string();
        let mut rows:Vec<(String,i64)>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_as("SELECT label,total FROM mdm_assets.asset_query_facets WHERE tenant_id=$1::uuid AND run=$2::uuid AND kind=$3 AND ($4::text IS NULL OR label>$4 COLLATE \"C\") ORDER BY label LIMIT $5")
                .bind(tenant).bind(task.to_string()).bind(facet.as_str()).bind(after).bind((limit + 1) as i64).fetch_all(c).await
        })).await?;
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = rows
            .last()
            .filter(|_| more)
            .map(|(label, _)| {
                self.next_query_cursor(
                    task,
                    scope,
                    Position::Facet {
                        facet,
                        label: label.clone(),
                    },
                )
            })
            .transpose()?;
        Ok(Response::Facets {
            task,
            facet,
            items: rows
                .into_iter()
                .map(|(label, total)| FacetCount {
                    label,
                    total: total as u64,
                })
                .collect(),
            next_cursor,
        })
    }
}

#[cfg(test)]
#[path = "../../tests/assets/query_read_unit.rs"]
mod tests;
