//! Authorized, immutable result reads. Cursor projection is part of its signature.
use super::*;
use rss_mdm_query::cursor::CursorCodec;
use serde::{Deserialize, Serialize};
use sqlx::Row;
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Position {
    Items {
        device: rss_mdm_agent_wire::DeviceId,
    },
    Facet {
        facet: Facet,
        label: String,
    },
}
struct QueryState {
    fields: Vec<FieldKey>,
    cut: AssetCut,
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
        if state.input.software.is_some() {
            return Err(Error::NotFound.into());
        }
        let owner = state.input.scope;
        let completed = state.completed;
        let failure = state.failure;
        let forwarded = state.started;
        if !scope.permits_query(&state.input.query)
            || owner.subject != scope.subject
            || owner.collection_scope != scope.collection_scope
            || owner.devices != scope.devices
        {
            return Err(Error::Forbidden.into());
        }
        let protected = state.input.query.personnel_fields();
        let mappings: BTreeSet<_> = protected
            .iter()
            .filter_map(|key| match rss_mdm_inventory::personnel::attribute(*key) {
                Some((_, rss_mdm_inventory::personnel::Attribute::Profile(id))) => Some(id),
                _ => None,
            })
            .collect();
        if !mappings.is_empty() {
            let expected = mappings.len() as i64;
            let count: i64 = tx.with_connection(move |c| Box::pin(async move {
                sqlx::query_scalar("SELECT count(*) FROM mdm_user_profiles.device_fields WHERE field_id=ANY($1)")
                    .bind(mappings.into_iter().collect::<Vec<_>>()).fetch_one(c).await
            })).await?;
            if count != expected {
                return Err(Error::Forbidden.into());
            }
        }
        let fields = protected.into_iter().collect();
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
            fields,
            cut: state.input.asset_cut,
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
            result_url: state.ready.then(|| {
                format!(
                    "/api/v1/tenants/{}/device-queries/{task}/items",
                    tx.tenant_id()
                )
            }),
        })
    }
    fn query_cursor(
        &self,
        tenant: rss_request_context::TenantId,
        token: &str,
        task: Uuid,
        scope: &ReadScope,
    ) -> Result<Position> {
        let codec = CursorCodec::from_key(self.asset_cursor_key.clone());
        let binding = digest(&("asset-results", tenant.to_string(), task, scope))?;
        codec
            .decode(
                &checked_input(rss_contract::PageCursor::parse(token))?,
                &binding,
            )
            .map_err(|_| Error::Conflict.into())
    }
    fn next_query_cursor(
        &self,
        tenant: rss_request_context::TenantId,
        task: Uuid,
        scope: &ReadScope,
        position: Position,
    ) -> Result<String> {
        let codec = CursorCodec::from_key(self.asset_cursor_key.clone());
        let binding = digest(&("asset-results", tenant.to_string(), task, scope))?;
        Ok(checked_input(codec.encode(&binding, &position))?
            .as_str()
            .to_owned())
    }
    pub(super) async fn asset_query_items(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        scope: &ReadScope,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Response> {
        if !(1..=1024).contains(&limit) {
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
            match self.query_cursor(tx.tenant_id(), token, task, scope)? {
                Position::Items { device } => Some(device),
                _ => return Err(Error::Conflict.into()),
            }
        } else {
            None
        };
        let tenant = tx.tenant_id().to_string();
        let metadata=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT device,octet_length(document) AS bytes FROM mdm_assets.asset_query_results WHERE tenant_id=$1::uuid AND run=$2::uuid AND ($3::uuid IS NULL OR (sort_key,device)>(SELECT sort_key,device FROM mdm_assets.asset_query_results WHERE tenant_id=$1::uuid AND run=$2::uuid AND device=$3)) ORDER BY sort_key,device LIMIT $4")
                .bind(tenant).bind(task.to_string()).bind(after_device.map(|id|id.into_uuid())).bind((limit + 1) as i64).fetch_all(c).await
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
            let device: rss_mdm_agent_wire::DeviceId =
                row.try_get::<uuid::Uuid, _>("device").and_then(|id| {
                    rss_mdm_agent_wire::DeviceId::try_from(id)
                        .map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?;
            next = Some(Position::Items { device });
            ids.push(device);
            bytes += size;
        }
        if !more {
            next = None;
        }
        let mut personnel = if state.fields.is_empty() {
            BTreeMap::new()
        } else {
            let now = self
                .clock
                .unix_seconds()
                .ok_or(Error::Unavailable(Failure::AssetsStorage))?;
            let mut facts =
                personnel::load_in(tx, &state.cut, now, true, &ids, &state.fields).await?;
            let devices: Vec<_> = facts.keys().map(|d| d.into_uuid()).collect();
            let mut qualified = BTreeMap::new();
            if !devices.is_empty() {
                let users = self
                    .users
                    .read(
                        binding,
                        &devices,
                        rss_request_context::Deadline::at(
                            std::time::Instant::now() + tx.deadline().timeout(),
                        ),
                    )
                    .await?;
                for u in users {
                    let device = crate::database::device_id(u.device)?;
                    if let Some(mut fields) = facts.remove(&device) {
                        fields.retain(|key, fact| u.qualifies(*key, fact));
                        qualified.insert(device, fields);
                    }
                }
            }
            qualified
        };
        let tenant = tx.tenant_id().to_string();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT r.device,r.document,r.digest FROM unnest($3::uuid[]) WITH ORDINALITY p(device,n) JOIN mdm_assets.asset_query_results r ON r.device=p.device WHERE r.tenant_id=$1::uuid AND r.run=$2::uuid ORDER BY p.n")
                .bind(tenant).bind(task.to_string()).bind(ids.iter().map(|id|id.into_uuid()).collect::<Vec<_>>()).fetch_all(c).await
        })).await?;
        rss_mdm_query_postgres::observe_rows("assets.results", &rows)?;
        let mut items = Vec::new();
        for row in rows {
            let raw: Vec<u8> = row.try_get("document")?;
            if Sha256::digest(&raw).as_slice() != row.try_get::<Vec<u8>, _>("digest")? {
                return Err(Error::Unavailable(Failure::AssetsStorage).into());
            }
            let mut item: DeviceView = stored(serde_json::from_slice(&raw))?;
            if item.device
                != row.try_get::<uuid::Uuid, _>("device").and_then(|id| {
                    rss_mdm_agent_wire::DeviceId::try_from(id)
                        .map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })?
            {
                return Err(Error::Unavailable(Failure::AssetsStorage).into());
            }
            let facts = personnel.remove(&item.device).unwrap_or_default();
            for &key in &state.fields {
                if facts.get(&key).is_none_or(|f| f.value.is_none()) {
                    if let Some(field) = item.fields.get_mut(&key) {
                        field.state = rss_mdm_inventory::State::Missing;
                    }
                    item.revisions.remove(&key);
                }
            }
            items.push(item);
        }
        Ok(Response::Page {
            items,
            next_cursor: next
                .map(|position| self.next_query_cursor(tx.tenant_id(), task, scope, position))
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
        if !(1..=1024).contains(&limit) {
            return Err(Error::Malformed.into());
        }
        if !self.query_state_in(tx, task, scope).await?.ready {
            return Err(Error::Conflict.into());
        }
        let after = if let Some(token) = cursor {
            match self.query_cursor(tx.tenant_id(), token, task, scope)? {
                Position::Facet {
                    facet: bound,
                    label,
                } if bound == facet => Some(label),
                _ => return Err(Error::Conflict.into()),
            }
        } else {
            None
        };
        let tenant = tx.tenant_id().to_string();
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
                    tx.tenant_id(),
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
