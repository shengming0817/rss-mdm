//! Device-authorized discovery from existing immutable asset and collection history.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs (borrowed transaction, no commit owner).
//! ref: SeaORM 1.1.17 src/executor/paginator.rs (filter the selected working set before pagination).
use super::*;
use rss_mdm_query::cursor::CursorCodec;
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    kind: String,
    tenant: String,
    device: String,
    authority: String,
    asset_cut: AssetCut,
    after: String,
}

impl AssetService {
    pub(super) async fn inventory_scopes(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        access: &ReadScope,
        limit: usize,
        token: Option<&str>,
        candidate: &AssetCut,
    ) -> Result<Response> {
        checked_input(rss_observation::Id::new(device))?;
        if !(1..=1000).contains(&limit) {
            return Err(Error::Malformed.into());
        }
        if access
            .devices
            .as_ref()
            .is_some_and(|ids| !ids.contains(device))
        {
            return Err(Error::Forbidden.into());
        }
        let tenant = self.tenant.to_string();
        let target = device.to_owned();
        if !tx
            .with_connection(move |c| Box::pin(crate::device::read::exists(c, tenant, target)))
            .await?
        {
            return Err(Error::NotFound.into());
        }
        let current = candidate.clone();
        let tenant = self.tenant.to_string();
        let targets = vec![device.to_owned()];
        let sources = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::device::read::sources_at(c, tenant, targets, &current).await
                })
            })
            .await?;
        if sources.len() > 2000 {
            return Err(Error::Unavailable(Failure::AssetSourceLimit).into());
        }
        let sources = sources
            .into_iter()
            .map(|row| {
                Ok(serde_json::json!({
                    "registration":row.try_get::<String,_>("registration")?,
                    "generation":row.try_get::<String,_>("generation")?,
                    "source":row.try_get::<String,_>("source")?,
                    "epoch":row.try_get::<String,_>("epoch")?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let catalog = catalog_at_in(tx, self.tenant, candidate).await?;
        let visible = catalog
            .fields()
            .filter(|f| f.sensitivity != rss_mdm_inventory::Sensitivity::Secret)
            .map(|f| f.key.as_str().to_owned())
            .collect::<Vec<_>>();
        let authority = digest(&(access, &sources, &visible))?;
        let (cut, after) = if let Some(token) = token {
            let cursor = self.scope_cursor(token, device, &authority)?;
            (cursor.asset_cut, cursor.after)
        } else {
            (candidate.clone(), String::new())
        };
        let catalog = catalog_at_in(tx, self.tenant, &cut).await?;
        let fields = catalog
            .fields()
            .filter(|f| visible.iter().any(|key| key == f.key.as_str()))
            .map(|f| f.key.as_str().to_owned())
            .collect::<Vec<_>>();
        let tenant = self.tenant.to_string();
        let projection = rss_mdm_inventory_postgres::projection_scope(self.tenant);
        let page_cut = cut.clone();
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, String>(SCOPES)
                        .bind(tenant)
                        .bind(serde_json::json!(sources))
                        .bind(page_cut.to_json())
                        .bind(fields)
                        .bind(after)
                        .bind((limit + 1) as i64)
                        .bind(projection.source().source())
                        .bind(projection.generation())
                        .fetch_all(c)
                        .await
                })
            })
            .await?;
        let more = rows.len() > limit;
        let selected = rows.into_iter().take(limit).collect::<Vec<_>>();
        let next_cursor = if more {
            let cursor = Cursor {
                kind: "inventory-scopes-v1".into(),
                tenant: self.tenant.to_string(),
                device: device.into(),
                authority,
                asset_cut: cut.clone(),
                after: selected.last().ok_or(Error::Malformed)?.clone(),
            };
            Some(
                checked_input(
                    CursorCodec::from_key(self.asset_cursor_key.clone())
                        .encode("inventory-scopes", &cursor),
                )?
                .as_str()
                .to_owned(),
            )
        } else {
            None
        };
        let items = selected
            .into_iter()
            .map(|value| {
                let scope: rss_mdm_inventory::CollectionScope =
                    stored(serde_json::from_str(&value))?;
                stored(scope.validate_executable())?;
                Ok(InventoryScope { scope })
            })
            .collect::<Result<_>>()?;
        Ok(Response::InventoryScopes {
            device: device.into(),
            asset_cut: cut,
            items,
            next_cursor,
        })
    }

    fn scope_cursor(&self, token: &str, device: &str, authority: &str) -> Result<Cursor> {
        if token.len() > 65536 {
            return Err(Error::Malformed.into());
        }
        let cursor: Cursor = CursorCodec::from_key(self.asset_cursor_key.clone())
            .decode(
                &checked_input(rss_contract::PageCursor::parse(token))?,
                "inventory-scopes",
            )
            .map_err(|_| Error::Conflict)?;
        if cursor.kind != "inventory-scopes-v1"
            || cursor.tenant != self.tenant.to_string()
            || cursor.device != device
            || cursor.authority != authority
            || cursor.asset_cut.tenant().to_string() != self.tenant.to_string()
        {
            return Err(Error::Conflict.into());
        }
        Ok(cursor)
    }
}

const SCOPES: &str = r#"
WITH authority AS (
 SELECT registration,source,epoch FROM jsonb_to_recordset($2::jsonb)
 AS a(registration text,source text,epoch text)
), streams AS (
 SELECT h.scope FROM mdm_access.collection_history h
 JOIN authority a ON a.registration=h.scope::jsonb->>'registration'
   AND a.source=h.scope::jsonb->>'source' AND a.epoch=h.scope::jsonb->>'epoch'
 WHERE h.tenant_id=$1::uuid AND mdm.asset_visible($3::jsonb,h.revision)
 UNION
 SELECT c.identity->>'scope' FROM mdm.asset_changes c
 JOIN authority a ON a.registration=c.identity->>'registration'
   AND a.source=(c.identity->>'scope')::jsonb->>'source'
   AND a.epoch=(c.identity->>'scope')::jsonb->>'epoch'
 WHERE c.tenant_id=$1::uuid AND c.kind='inventory' AND mdm.asset_visible($3::jsonb,c.revision)
), requested AS (
 SELECT sha256(convert_to(jsonb_build_array($7::text,$8::text,s.scope)::text,'UTF8')) AS digest
 FROM streams s
), inventory AS (
 SELECT DISTINCT ON(h.scope_digest,h.field,h.field_scope)
   h.field_scope,h.document
 FROM mdm.inventory_history h JOIN requested q ON q.digest=h.scope_digest
 WHERE h.tenant_id=$1::uuid AND mdm.asset_visible($3::jsonb,h.revision) AND h.field=ANY($4::text[])
 ORDER BY h.scope_digest,h.field,h.field_scope,h.revision DESC
), facts AS (
 SELECT (h.field_scope::jsonb)::text AS scope FROM inventory h
 JOIN authority a ON a.registration=h.document->>'registration'
   AND a.source=h.document->>'source' AND a.epoch=h.document->>'epoch'
 WHERE h.document IS NOT NULL AND h.document->>'state'<>'deleted'
   AND h.document->>'journal'=$7 AND h.document->>'generation'=$8
), runs AS (
 SELECT DISTINCT ON(h.scope,h.run) h.scope,h.run,h.sequence,h.document
 FROM mdm_access.collection_history h
 WHERE h.tenant_id=$1::uuid AND h.scope IN(SELECT scope FROM streams) AND mdm.asset_visible($3::jsonb,h.revision)
 ORDER BY h.scope,h.run,h.revision DESC
), attempts AS (
 SELECT DISTINCT ON(h.scope,f->'definition'->>'key',f->'scope')
   f->'scope' AS scope,
   (v.metadata->'fields'->(f->'definition'->>'key')->>'quality') AS quality
 FROM runs h
 JOIN authority a ON a.registration=h.scope::jsonb->>'registration'
   AND a.source=h.scope::jsonb->>'source' AND a.epoch=h.scope::jsonb->>'epoch'
 JOIN mdm_access.collection_versions v ON v.tenant_id=$1::uuid AND v.version=h.document->>'progress_version'
 CROSS JOIN LATERAL jsonb_array_elements(v.metadata->'definition'->'fields') f
 WHERE h.document IS NOT NULL AND f->'definition'->>'key'=ANY($4::text[])
 ORDER BY h.scope,f->'definition'->>'key',f->'scope',h.sequence DESC,h.run DESC
), candidates AS (
 SELECT scope FROM facts
 UNION SELECT scope::text FROM attempts WHERE quality<>'deleted'
)
SELECT scope FROM candidates WHERE scope::jsonb->>'kind'<>'device'
 AND scope COLLATE "C">$5::text COLLATE "C"
ORDER BY scope COLLATE "C" LIMIT $6
"#;
