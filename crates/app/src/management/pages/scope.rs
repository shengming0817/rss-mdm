use super::*;
use sqlx::Row;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::management) struct ScopePage {
    result: Uuid,
    scope: Uuid,
    current: bool,
    total_objects: u64,
    total_members: u64,
    sources: Vec<automation::SourceSet>,
    page: ScopeItems,
    next_cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ScopeItems {
    Members { items: Vec<String> },
    Decisions { items: Vec<ScopeDecision> },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeDecision {
    device: String,
    identity: Identity,
    reasons: Vec<Reason>,
    sources: Vec<usize>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Identity {
    Active,
    Inactive,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    MissingLimitationMatch,
    ExplicitExclusion,
}
impl Management {
    pub(in crate::management) async fn scope_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Uuid,
        result: Uuid,
        kind: ScopePageKind,
        query: &PageQuery,
    ) -> Result<Value> {
        if !(1..=1000).contains(&query.limit) {
            return Err(Error::Malformed.into());
        }
        let tenant = self.tenant.to_string();
        let binding = ResultBinding::Scope { scope, kind };
        let after = query
            .cursor
            .as_ref()
            .map(|token| decode(&self.asset_cursor_key, token, &tenant, result, &binding))
            .transpose()?;
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT r.phase,r.object_count,r.member_count,r.input::text,(s.resolution=r.id) AS current FROM mdm_management.scope_runs r JOIN mdm_management.scopes s ON (s.tenant_id,s.id)=(r.tenant_id,r.scope) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.scope=$3::uuid AND NOT s.deleted")
                .bind(tenant).bind(result.to_string()).bind(scope.to_string()).fetch_optional(c).await
        })).await?.ok_or(Error::NotFound)?;
        if row.try_get::<&str, _>("phase")? != "published" {
            return Err(Error::Conflict.into());
        }
        let frozen: automation::ScopeInput = stored(serde_json::from_str(row.try_get("input")?))?;
        let tenant = self.tenant.to_string();
        let members = kind == ScopePageKind::Members;
        let limit = query.limit as i64;
        let metadata=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT device,octet_length(explanation::text) AS bytes FROM mdm_management.scope_results WHERE tenant_id=$1::uuid AND run=$2::uuid AND (NOT $3 OR matched) AND ($4::text IS NULL OR device>$4 COLLATE \"C\") ORDER BY device LIMIT $5")
                .bind(tenant).bind(result.to_string()).bind(members).bind(after).bind(limit).fetch_all(c).await
        })).await?;
        let mut devices = Vec::new();
        let mut bytes = 0usize;
        for item in metadata {
            let size = if members {
                1024
            } else {
                item.try_get::<i32, _>("bytes")? as usize + 1024
            };
            if bytes + size > 14 * 1024 * 1024 {
                break;
            }
            bytes += size;
            devices.push(item.try_get::<String, _>("device")?);
        }
        let next_cursor = devices
            .last()
            .cloned()
            .map(|after| {
                encode(
                    &self.asset_cursor_key,
                    Cursor {
                        tenant: self.tenant.to_string(),
                        result,
                        binding,
                        after,
                    },
                )
            })
            .transpose()?;
        let page = if members {
            ScopeItems::Members { items: devices }
        } else {
            let tenant = self.tenant.to_string();
            let rows:Vec<(String,String)>=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_as("SELECT device,explanation::text FROM mdm_management.scope_results WHERE tenant_id=$1::uuid AND run=$2::uuid AND device=ANY($3) ORDER BY device")
                    .bind(tenant).bind(result.to_string()).bind(devices).fetch_all(c).await
            })).await?;
            let mut items = Vec::new();
            for (device, raw) in rows {
                let item: ScopeDecision = stored(serde_json::from_str(&raw))?;
                if item.device != device
                    || item
                        .sources
                        .iter()
                        .any(|index| *index >= frozen.sources.len())
                {
                    return Err(Error::Unavailable(Failure::ManagementStorage).into());
                }
                items.push(item);
            }
            ScopeItems::Decisions { items }
        };
        json(&ScopePage {
            result,
            scope,
            current: row.try_get::<Option<bool>, _>("current")?.unwrap_or(false),
            total_objects: row.try_get::<i64, _>("object_count")? as u64,
            total_members: row.try_get::<i64, _>("member_count")? as u64,
            sources: frozen.sources,
            page,
            next_cursor,
        })
    }
}
