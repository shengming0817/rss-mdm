//! Authorized, immutable result reads. Cursor projection is part of its signature.
use super::super::automation::JobInput;
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sqlx::Row;
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Position {
    Items { key: Vec<u8>, device: String },
    Facet { facet: Facet, label: String },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    tenant: String,
    task: Uuid,
    scope: String,
    position: Position,
}
struct QueryState {
    summary: Summary,
    status: String,
    failure: Option<String>,
    ready: bool,
}
impl Management {
    async fn query_state_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        scope: &ReadScope,
    ) -> Result<QueryState> {
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT j.input::text,j.completed,j.forwarded,j.failure,r.total,r.matched,r.unknown FROM mdm_management.asset_query_runs r JOIN mdm_management.automation_jobs j ON (j.tenant_id,j.id)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND j.kind='asset_query'")
                .bind(tenant).bind(task.to_string()).fetch_optional(c).await
        })).await?.ok_or(Error::NotFound)?;
        let job: JobInput = stored(serde_json::from_str(row.try_get("input")?))?;
        let JobInput::AssetQuery { scope: owner, .. } = job else {
            return Err(Error::Unavailable(Failure::ManagementStorage).into());
        };
        if &owner != scope {
            return Err(Error::Forbidden.into());
        }
        let completed: bool = row.try_get("completed")?;
        let failure: Option<String> = row.try_get("failure")?;
        let status = if failure.is_some() {
            "failed"
        } else if completed {
            "completed"
        } else if row.try_get("forwarded")? {
            "running"
        } else {
            "pending"
        };
        Ok(QueryState {
            summary: Summary {
                total: row.try_get::<i64, _>("total")? as usize,
                matched: row.try_get::<i64, _>("matched")? as usize,
                unknown: row.try_get::<i64, _>("unknown")? as usize,
            },
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
                .then(|| format!("/api/v2/device-queries/{task}/items")),
        })
    }
    fn query_cursor(&self, token: &str, task: Uuid, scope: &ReadScope) -> Result<Position> {
        if token.len() > 4096 {
            return Err(Error::Malformed.into());
        }
        let bytes = input(URL_SAFE_NO_PAD.decode(token))?;
        if bytes.len() <= 32 {
            return Err(Error::Malformed.into());
        }
        let (payload, signature) = bytes.split_at(bytes.len() - 32);
        ring::hmac::verify(&self.asset_cursor_key, payload, signature)
            .map_err(|_| Error::Conflict)?;
        let cursor: Cursor = input(serde_json::from_slice(payload))?;
        if cursor.tenant != self.tenant.to_string()
            || cursor.task != task
            || cursor.scope != digest(scope)?
        {
            return Err(Error::Conflict.into());
        }
        Ok(cursor.position)
    }
    fn next_query_cursor(
        &self,
        task: Uuid,
        scope: &ReadScope,
        position: Position,
    ) -> Result<String> {
        let cursor = Cursor {
            tenant: self.tenant.to_string(),
            task,
            scope: digest(scope)?,
            position,
        };
        let mut bytes = input(serde_json::to_vec(&cursor))?;
        let signature = ring::hmac::sign(&self.asset_cursor_key, &bytes);
        bytes.extend(signature.as_ref());
        Ok(URL_SAFE_NO_PAD.encode(bytes))
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
        let (after_key, after_device) = if let Some(token) = cursor {
            match self.query_cursor(token, task, scope)? {
                Position::Items { key, device } => (Some(key), Some(device)),
                _ => return Err(Error::Conflict.into()),
            }
        } else {
            (None, None)
        };
        let tenant = self.tenant.to_string();
        let metadata=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT device,sort_key,octet_length(document) AS bytes FROM mdm_management.asset_query_results WHERE tenant_id=$1::uuid AND run=$2::uuid AND ($3::bytea IS NULL OR (sort_key,device)>($3,$4 COLLATE \"C\")) ORDER BY sort_key,device LIMIT $5")
                .bind(tenant).bind(task.to_string()).bind(after_key).bind(after_device).bind(limit as i64).fetch_all(c).await
        })).await?;
        let mut ids = Vec::new();
        let mut bytes = 0usize;
        let mut next = None;
        for row in metadata {
            let size = row.try_get::<i32, _>("bytes")? as usize + 1024;
            if bytes + size > 16 * 1024 * 1024 {
                break;
            }
            let device: String = row.try_get("device")?;
            next = Some(Position::Items {
                key: row.try_get("sort_key")?,
                device: device.clone(),
            });
            ids.push(device);
            bytes += size;
        }
        let tenant = self.tenant.to_string();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT r.device,r.document,r.digest FROM unnest($3::text[]) WITH ORDINALITY p(device,n) JOIN mdm_management.asset_query_results r ON r.device=p.device WHERE r.tenant_id=$1::uuid AND r.run=$2::uuid ORDER BY p.n")
                .bind(tenant).bind(task.to_string()).bind(ids).fetch_all(c).await
        })).await?;
        let mut items = Vec::new();
        for row in rows {
            let raw: Vec<u8> = row.try_get("document")?;
            if Sha256::digest(&raw).as_slice() != row.try_get::<Vec<u8>, _>("digest")? {
                return Err(Error::Unavailable(Failure::ManagementStorage).into());
            }
            let item: DeviceView = stored(serde_json::from_slice(&raw))?;
            if item.device != row.try_get::<String, _>("device")? {
                return Err(Error::Unavailable(Failure::ManagementStorage).into());
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
        let rows:Vec<(String,i64)>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_as("SELECT label,total FROM mdm_management.asset_query_facets WHERE tenant_id=$1::uuid AND run=$2::uuid AND kind=$3 AND ($4::text IS NULL OR label>$4 COLLATE \"C\") ORDER BY label LIMIT $5")
                .bind(tenant).bind(task.to_string()).bind(facet.as_str()).bind(after).bind(limit as i64).fetch_all(c).await
        })).await?;
        let next_cursor = rows
            .last()
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
